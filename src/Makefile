# SPDX-License-Identifier: GPL-2.0-only
obj-m := crypto-hw-eip93.o

crypto-hw-eip93-y := eip93-main.o eip93-ring.o eip93-common.o

crypto-hw-eip93-$(CONFIG_EIP93_AES) += eip93-aes.o
crypto-hw-eip93-$(CONFIG_EIP93_DES) += eip93-des.o
crypto-hw-eip93-$(CONFIG_EIP93_AEAD) += eip93-aead.o
crypto-hw-eip93-$(CONFIG_EIP93_PRNG) += eip93-prng.o
