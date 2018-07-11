################################################################################
#
# Xilinx Linux Network DMA Driver
#
################################################################################

XLNX_NET_DRV_VERSION = 1.0
XLNX_NET_DRV_SITE = path_to_driver's_source_folder
XLNX_NET_DRV_SITE_METHOD = local
XLNX_NET_DRV_DEPENDENCIES = linux

define XLNX_NET_DRV_BUILD_CMDS
	$(MAKE) $(LINUX_MAKE_FLAGS) CC=$(TARGET_CC) -C $(@D) KERNELDIR=$(LINUX_DIR) modules
endef

define XLNX_NET_DRV_INSTALL_TARGET_CMDS
	$(MAKE) $(LINUX_MAKE_FLAGS) CC=$(TARGET_CC) -C $(@D) KERNELDIR=$(LINUX_DIR) modules_install
endef

$(eval $(kernel-module))
$(eval $(generic-package))
