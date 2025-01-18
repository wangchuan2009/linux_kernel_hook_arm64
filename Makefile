MODULE_NAME := hack
RESMAN_CORE_OBJS:=main.o
RESMAN_GLUE_OBJS:=
ifneq ($(KERNELRELEASE),)
	obj-m := $(MODULE_NAME).o
	$(MODULE_NAME)-objs:=$(RESMAN_GLUE_OBJS) $(RESMAN_CORE_OBJS)
else
	KDIR := /home/wangchuan/Xiaomi_Kernel_OpenSource
all:
	make -j$(nproc) -C $(KDIR) M=$(shell pwd) ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- modules
	rm -rf *.o *.mod .*.*.cmd *.mod.o *.mod.c *.symvers *.order .tmp_versions
clean:
	rm -rf *.ko *.o *.mod .*.*.cmd *.mod.o *.mod.c *.symvers *.order *.lds .tmp_versions
.PHONY: clean
endif
