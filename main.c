#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/syscalls.h>
#include <asm/tlbflush.h>
#include <linux/version.h>


#define bits(n, high, low) (((n) << (63u - (high))) >> (63u - (high) + (low)))

typedef asmlinkage long (*syscall_ioctl_t)(unsigned int fd, unsigned int cmd, unsigned long arg);//4.14版本的ioctl是通过栈传递 所以fd cmd 和arg是三个参数 asmlinkage的意思是指定这个函数是由栈传递的参数
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
typedef long (*new_syscall_ioctl_t)(const struct pt_regs *);//4.19版本以上通过寄存器传递参数所以不用加asmlinkage 默认不加就是通过寄存器传递参数
kallsyms_lookup_name_t (*my_kallsyms_lookup_name)(const char *name);
unsigned long *__sys_call_table;
unsigned long start_address;
unsigned long finish_address;
syscall_ioctl_t original_ioctl;//保存低版本ioctl

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 14, 186)
    new_syscall_ioctl_t new_original_ioctl;//保存高版本ioctl
#endif

static int setts(int value) {
    struct file *file;
    loff_t pos = 0;
    char buf[2];

    file = filp_open("/proc/sys/kernel/kptr_restrict", O_WRONLY, 0);
    if (IS_ERR(file)) {
        printk(KERN_ERR "Failed to open /proc/sys/kernel/kptr_restrict\n");
        return -EFAULT;
    }

    snprintf(buf, sizeof(buf), "%d", value);

    kernel_write(file, buf, strlen(buf), &pos);

    filp_close(file, NULL);

    return 0;
}
static uintptr_t read_kallsyms(const char *symbol) {
    struct file *file;
    loff_t pos = 0;
    char *buf;
    char sym_name[256];
	char *addr_str;
    char *type_str;
	char *name_str;
    uintptr_t addr;
    char type;
    mm_segment_t old_fs;
    struct seq_file *seq;
    file = filp_open("/proc/kallsyms", O_RDONLY, 0);
    if (IS_ERR(file)) {
        printk(KERN_ERR "无法打开kallsyms\n");
        return -EFAULT;
    }

    old_fs = get_fs();
    set_fs(get_ds());

    buf = kmalloc(4096, GFP_KERNEL);
    if (!buf) {
        filp_close(file, NULL);
        set_fs(old_fs);
        return -ENOMEM;
    }

    seq = file->private_data;
    if (!seq) {
        printk(KERN_ERR "失败\n");
        kfree(buf);
        filp_close(file, NULL);
        set_fs(old_fs);
        return -EFAULT;
    }

    while (seq_read(file, buf, 4096, &pos) > 0) {
        char *line = buf;
        while (*line) {
            char *end = strchr(line, '\n');
            if (end) *end = '\0';
            addr_str = line;
            type_str = strchr(line, ' ');
            if (!type_str) break;
            *type_str++ = '\0';
            name_str = strchr(type_str, ' ');
            if (!name_str) break;
            *name_str++ = '\0';

            addr = simple_strtoull(addr_str, NULL, 16);
            type = *type_str;
            strncpy(sym_name, name_str, sizeof(sym_name) - 1);
            sym_name[sizeof(sym_name) - 1] = '\0';

            if (strcmp(sym_name, symbol) == 0) {
                //printk(KERN_INFO "Torlins Symbol: %s, Address: %llx, Type: %c\n", sym_name, addr, type);
                kfree(buf);
                filp_close(file, NULL);
                set_fs(old_fs);
                return addr;      
            }

            if (end) line = end + 1;
            else break;
        }
    }
    return -1;
}
unsigned long get_kallsyms_lookup_name_addr(void)
{
	unsigned long ret = 0;
	setts(0);
	ret = read_kallsyms("kallsyms_lookup_name");
	return ret;
}

static uint64_t page_size_t = 0;
static uint64_t page_level_c = 0;
static uint64_t page_shift_t = 0;

static uint64_t pgd_k_pa = 0;
static uint64_t pgd_k = 0;

__attribute__((no_sanitize("cfi"))) void init_page_util(void)
{
    uint64_t tcr_el1;
    uint64_t ttbr1_el1;
    uint64_t va_bits;
  
    uint64_t t1sz;
    uint64_t tg1;
    uint64_t baddr;
    uint64_t page_size_mask;
    //util_find_kallsyms();
   // printk("[db] kallsyms_lookup_name_fun_: %lx\n", kallsyms_lookup_name_fun_);
    asm volatile("mrs %0, tcr_el1" : "=r"(tcr_el1));

    t1sz = bits(tcr_el1, 21, 16);
    
    tg1 = bits(tcr_el1, 31, 30);

    va_bits = 64 - t1sz;

    page_shift_t = 12;
    if (tg1 == 1) {
        page_shift_t = 14;
    } else if (tg1 == 3) {
        page_shift_t = 16;
    }
    page_size_t = 1 << page_shift_t;

    page_level_c = (va_bits - 4) / (page_shift_t - 3);
    
    asm volatile("mrs %0, ttbr1_el1" : "=r"(ttbr1_el1));
    baddr = ttbr1_el1 & 0xFFFFFFFFFFFE;
    page_size_mask = ~(page_size_t - 1);
    pgd_k_pa = baddr & page_size_mask;
    pgd_k = (uint64_t)phys_to_virt(pgd_k_pa);
    printk("[db]page_size_t: %lx\n", page_size_t);
    printk("[db]page_level_c: %lx\n", page_level_c);
    printk("[db]page_shift_t: %lx\n", page_shift_t);
    printk("[db]pgd_k_pa: %lx\n", pgd_k_pa);
    printk("[db]pgd_k: %lx\n", pgd_k);
}


uint64_t *pgtable_entry(uint64_t pgd, uint64_t va)
{

    uint64_t pxd_bits = page_shift_t - 3;
    uint64_t pxd_ptrs = 1u << pxd_bits;
    uint64_t pxd_va = pgd;
    uint64_t pxd_pa = virt_to_phys((void*)pxd_va);
    uint64_t pxd_entry_va = 0;
    uint64_t block_lv = 0;
    int64_t lv = 0;
    //int64_t lv;
    if(page_shift_t == 0 || page_level_c == 0 || page_shift_t == 0)
        return NULL;
    // ================
    // Branch to some function (even empty), It can work,
    // I don't know why, if anyone knows, please let me know. thank you very much.
    // ================
    //__flush_dcache_area((void *)pxd_va, page_size_t);

    for (lv = 4 - page_level_c; lv < 4; lv++) {
        uint64_t pxd_shift = (page_shift_t - 3) * (4 - lv) + 3;
        uint64_t pxd_index = (va >> pxd_shift) & (pxd_ptrs - 1);
        pxd_entry_va = pxd_va + pxd_index * 8;
        if (!pxd_entry_va) return 0;
        uint64_t pxd_desc = *((uint64_t *)pxd_entry_va);
        if ((pxd_desc & 0b11) == 0b11) { // table
            pxd_pa = pxd_desc & (((1ul << (48 - page_shift_t)) - 1) << page_shift_t);
        } else if ((pxd_desc & 0b11) == 0b01) { // block
            // 4k page: lv1, lv2. 16k and 64k page: only lv2.
            uint64_t block_bits = (3 - lv) * pxd_bits + page_shift_t;
            pxd_pa = pxd_desc & (((1ul << (48 - block_bits)) - 1) << block_bits);
            block_lv = lv;
        } else { // invalid
            return 0;
        }
        //
        pxd_va = (uint64_t)phys_to_virt((phys_addr_t)pxd_pa);
        if (block_lv) {
            break;
        }
    }
#if 0
    uint64_t left_bit = page_shift + (block_lv ? (3 - block_lv) * pxd_bits : 0);
    uint64_t tpa = pxd_pa + (va & ((1u << left_bit) - 1));
    uint64_t tlva = phys_to_virt(tpa);
    uint64_t tkimg = phys_to_kimg(tpa);
    if (tlva != va && tkimg != va) {
        return 0;
    }
#endif
    return (uint64_t *)pxd_entry_va;
}

inline uint64_t *pgtable_entry_kernel(uint64_t va)
{
    return pgtable_entry(pgd_k, va);
}


long new_hook_ioctl(const struct pt_regs *kregs)
{
	long ret = 0;
    printk("gt_hook_successful_ioctl");
	ret = new_original_ioctl(kregs);
	return ret;
}

asmlinkage long hook_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg)
{
	long ret = 0;
	printk("gt_hook_ioctl");
	ret = original_ioctl(fd, cmd, arg);
	return ret;
}

static int hook_func(unsigned long hook_function, int nr,
        unsigned long *sys_table)
{
    uint64_t orginal_pte;
    uint64_t *pte;
    if(nr<0)
        return 3004;

    pte = pgtable_entry_kernel((uint64_t)&sys_table[nr]);
    if(pte == NULL)
        return 3007;
    
    
    orginal_pte = *pte;
    *pte = (orginal_pte | PTE_DBM) & ~PTE_RDONLY;
    flush_tlb_all();
    
    sys_table[nr] = hook_function;
    
    //orginal_pte = *pte;
    *pte = orginal_pte;
    flush_tlb_all();
}



static unsigned long *obtain_syscall_table_bf(unsigned long start_address, unsigned long finish_address, unsigned long sys_close_addr)
{
  	unsigned long *syscall_table;
	unsigned long int i;

	for (i = start_address; i < finish_address; i += sizeof(void *)) {
		syscall_table = (unsigned long *)i;
		if (syscall_table[__NR_close] == sys_close_addr)
			return syscall_table;
	}
	return NULL;
}

static int __init my_module_init(void) {
    #if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 14, 186)
    hook_func((unsigned long)hook_ioctl, __NR_ioctl, __sys_call_table);
    #else
    hook_func((unsigned long)new_hook_ioctl, __NR_ioctl, __sys_call_table);
    //__sys_call_table[__NR_ioctl] = (unsigned long)new_hook_ioctl;
    #endif
    
    return 0;
}

static void __exit my_module_exit(void) {
    #if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 14, 191)
    hook_func((unsigned long)original_ioctl, __NR_ioctl, __sys_call_table);
    #else
    hook_func((unsigned long)new_original_ioctl, __NR_ioctl, __sys_call_table);
    //__sys_call_table[__NR_ioctl] = (unsigned long)new_original_ioctl;;
    #endif
}

module_init(my_module_init);
module_exit(my_module_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Custom syscall module using kprobes");
MODULE_AUTHOR("wangchuan");