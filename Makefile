#
# Copyright (C) 2006-2019 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#


include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=mtk-eip93
PKG_RELEASE:=1.2

include $(INCLUDE_DIR)/package.mk

define KernelPackage/crypto-hw-eip93
  SECTION:=kernel
  CATEGORY:=Kernel modules
  SUBMENU:=Cryptographic API modules
  DEPENDS:= \
	@TARGET_ramips_mt7621 \
	+kmod-crypto-authenc \
	+kmod-crypto-des \
	+kmod-crypto-md5 \
	+kmod-crypto-sha1 \
	+kmod-crypto-sha256
  KCONFIG:=
  TITLE:=MTK EIP93 crypto module.
  FILES:=$(PKG_BUILD_DIR)/crypto-hw-eip93.ko
  AUTOLOAD:=$(call AutoProbe,crypto-hw-eip93)
  MENU:=1
endef

define KernelPackage/crypto-hw-eip93/config
if PACKAGE_kmod-crypto-hw-eip93

comment "Build options"

config CRYPTO_EIP93_AES
	bool "Register AES algorithm implementations with the Crypto API"
	default y
	select CRYPTO_AES
	select CRYPTO_BLKCIPHER
	select CRYPTO_CBC
	select CRYPTO_CTR
	select CRYPTO_ECB
	help
	  Selecting this will offload AES - ECB, CBC and CTR crypto
	  to the EIP-93 crypto engine.

config CRYPTO_EIP93_DES
	bool "Register legacy DES / 3DES algorithm with the Crypto API"
	default y
	select CRYPTO_BLKCIPHER
	select CRYPTO_LIB_DES
	help
	  Selecting this will offload DES and 3DES ECB and CBC
	  crypto to the EIP-93 crypto engine.

config CRYPTO_EIP93_AEAD
  	bool "Register AEAD algorithm with the Crypto API"
  	default y
	select CRYPTO_AEAD
	select CRYPTO_AUTHENC
	select CRYPTO_MD5
	select CRYPTO_SHA1
	select CRYPTO_SHA256
	help
  	  Selecting this will offload AEAD authenc(hmac(x), cipher(y))
	  crypto to the EIP-93 crypto engine.

config CRYPTO_EIP93_PRNG
  	bool "Register PRNG device with the Crypto API"
  	default y
	help
  	  Selecting this will add the ANSI X9.31 Pseudo Random Number Generator
	  of the EIP-93 crypto engine to the Crypto API
endif
endef

EXTRA_KCONFIG:= 

ifdef CONFIG_CRYPTO_EIP93_AES
	EXTRA_KCONFIG += CONFIG_EIP93_AES=y
	EXTRA_KCONFIG += CONFIG_EIP93_SKCIPHER=y
endif
ifdef CONFIG_CRYPTO_EIP93_DES
	EXTRA_KCONFIG += CONFIG_EIP93_DES=y
	EXTRA_KCONFIG += CONFIG_EIP93_SKCIPHER=y
endif
ifdef CONFIG_CRYPTO_EIP93_AEAD
	EXTRA_KCONFIG += CONFIG_EIP93_AEAD=y
endif
ifdef CONFIG_CRYPTO_EIP93_PRNG
	EXTRA_KCONFIG += CONFIG_EIP93_PRNG=y
endif

EXTRA_CFLAGS:= \
	$(patsubst CONFIG_%, -DCONFIG_%=1, $(patsubst %=m,%,$(filter %=m,$(EXTRA_KCONFIG)))) \
	$(patsubst CONFIG_%, -DCONFIG_%=1, $(patsubst %=y,%,$(filter %=y,$(EXTRA_KCONFIG)))) \

MAKE_OPTS:= \
	$(KERNEL_MAKE_FLAGS) \
	M="$(PKG_BUILD_DIR)" \
	EXTRA_CFLAGS="$(EXTRA_CFLAGS)" \
	$(EXTRA_KCONFIG)

define Build/Compile
	$(MAKE) -C "$(LINUX_DIR)" \
		$(MAKE_OPTS) \
		modules
endef

$(eval $(call KernelPackage,crypto-hw-eip93))
