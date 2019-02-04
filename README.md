# Mediatek EIP93 Crypto Engine

Initial attemps for the EIP-93 Crypto Engine Driver. This Crypto Engine is 
available in the Mediatek MT7621 SoC.

It enables hardware crypto for:
* DES-ECB/CBC
* 3DES-ECB/CBC
* AES-ECB/CBC/CTR with 128/192/256 keysize.

This should be added to your device DTS or better yet to the mt7621.dtsi:

	crypto: crypto@1E004000 {
		status = "okay";

		compatible = "mediatek,mtk-eip93";
		reg = <0x1E004000 0x1000>;

		interrupt-parent = <&gic>;
		interrupts = <GIC_SHARED 19 IRQ_TYPE_LEVEL_HIGH>;
	};

Work in progress at the moment: Still need work / cleanup

Rebased code on EIP-197 Safexcel code.

Removed depreciated ABLKCIPHER API and use SKCIPHER now.

BUG:crypto-blocks > PAGE_SIZE fail !!
	work around (while continue developing hash portion):
	Kernel page_size 16Kb

TODO:

MD5 / SHA1 / SHA 224 / SHA 256

HMAC( MD5 / SHA1 / SHA224 / SSH 256)

Authentication:

AEAD(HMAC(y),CBC(x))

