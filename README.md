# Mediatek EIP93 Crypto Engine

Linux Crypto Driver for the EIP-93. This Crypto engine is
available in the Mediatek MT7621 SoC.

This should be added to your device DTS or better yet to the mt7621.dtsi:

	crypto: crypto@1E004000 {
		status = "okay";

		compatible = "mediatek,mtk-eip93";
		reg = <0x1E004000 0x1000>;

		interrupt-parent = <&gic>;
		interrupts = <GIC_SHARED 19 IRQ_TYPE_LEVEL_HIGH>;
	};

It enables hardware crypto for:
* DES-ECB/CBC
* 3DES-ECB/CBC
* AES-ECB/CBC/CTR with 128/192/256 keysize.


Authentication:

AEAD(HMAC(MD5/SHA1/224/256, DES/3DES-CBC)
AEAD(HMAC(SHA1/224/256),CBC(AES))

Testing has been done on Linux Kernel v5.4.31 with all the extended tests enabled.
Sofar ALL tests are passed. However still issues getting this to work with IPSEC.

