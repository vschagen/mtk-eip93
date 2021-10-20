# mtk-eip93
Mediatek EIP93 Crypto driver

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

The 999-patch is to add the mtk-eip93 to the Kconfig / Make files in the drivers/crypto folder
Add the crypto/mtk-eip93 folder to the linux drivers

OR:

add the 999-patch to the OpenWrt /target/linux/ramips/patch-5.10 folder
and the crypto/mtk-eip93 folder to the /target/linux/files/drivers folder

Pending upstream merger.
