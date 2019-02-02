ifneq (${KERNELRELEASE},)

# Kernel build

EXTRA_CFLAGS += -O2

crypto-hw-eip93-objs :=	eip93-core.o \
			eip93-ring.o \
			eip93-cipher.o \
			eip93-prng.o 
#			eip93-hash.o

obj-m += crypto-hw-eip93.o

else

# Out of tree build

ifneq ($(DKMS_KERNEL_VERSION),)
KERNELVER = $(DKMS_KERNEL_VERSION)
else
KERNELVER ?= $(shell uname -r)
endif

KERNEL_SOURCE ?= /lib/modules/$(KERNELVER)/build

modules default:
	${MAKE} -C ${KERNEL_SOURCE} SUBDIRS=${PWD} modules

modules_install:
	$(MAKE) -C $(KERNEL_SOURCE) SUBDIRS=${PWD} modules_install

clean:
	${MAKE} -C ${KERNEL_SOURCE} SUBDIRS=${PWD} clean

endif

