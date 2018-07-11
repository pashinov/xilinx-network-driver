#
# Makefile
#

obj-m := xlnx-network-drv.o
PWD := $(shell pwd)

all: modules

modules:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

modules_install:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) INSTALL_MOD_PATH=$(TARGET_DIR) modules_install