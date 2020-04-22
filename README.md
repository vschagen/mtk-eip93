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
* des ecb/cbc
* 3des ecb/cbc
* aes ecb / cbc / ctr /rfc3686 with 128/192/256 keysize.


Authentication:
* authenc(hmac(md5/sha1/sha224/sha256), des / 3des - cbc)
* authenc(hmac(md5/sha1/224/256, des / 3des - cbc)
* authenc(hmac(sha1/sha256), cbc / ctr /rfc3686 - aes) with 128/192/256 keysize

Testing has been done on Linux Kernel v5.4.33 with all the extended tests enabled.
