CONFIG_NVME_TCP=m
obj-$(CONFIG_NVME_TCP)			+= nvme-tcp.o

nvme-tcp-y				+= tcp.o

clean:
	rm -f $(DRIVER).ko.unsigned Module.markers Module.symvers modules.order
	rm -f *.o *.ko *.mod.o *.mod.c .*.cmd
	rm -rf .tmp_versions
