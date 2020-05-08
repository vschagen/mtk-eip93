# Mediatek EIP93 Crypto Engine

Linux Crypto Driver for the EIP-93. This Crypto engine is
available in the Mediatek MT7621 SoC.

This should be added to your device DTS or better yet to the mt7621.dtsi:

	crypto: crypto@1e004000 {
		status = "okay";

		compatible = "mediatek,mtk-eip93";
		reg = <0x1e004000 0x1000>;

		interrupt-parent = <&gic>;
		interrupts = <GIC_SHARED 19 IRQ_TYPE_LEVEL_HIGH>;
	};

It enables hardware crypto for:
* des ecb/cbc
* 3des ecb/cbc
* aes ecb / cbc / ctr /rfc3686 with 128/192/256 keysize.


Authentication:
* authenc(hmac(md5/sha1/sha224/sha256), des / 3des - cbc)
* authenc(hmac(md5/sha1/224/256, des / 3des - cbc)
* authenc(hmac(sha1/sha256), cbc / rfc3686(ctr) - aes) with 128/192/256 keysize

Testing has been done on Linux Kernel v5.4.39 with all the extended tests enabled.

TODO:
finish the ansi prng implementation. To be able to seed the PRNG from userspace
for ESP offload later on.

implement the xfrm esp offload callbacks and use with the mtk ethernet driver

improve performance, reduce code and minimalize structures

add ahash implemention for simple sha1/256 and hmac(sha1/sha256)
