# [wireguard-tools-se](https://git.zx2c4.com/wireguard-tools/about/) &mdash; tools for configuring [wireguard-se](https://github.com/kmwebnet/wireguard-se)

This supplies the main userspace tooling for using and configuring WireGuard
tunnels, including the
[`wg(8)`](https://git.zx2c4.com/wireguard-tools/about/src/man/wg.8) and
[`wg-quick(8)`](https://git.zx2c4.com/wireguard-tools/about/src/man/wg-quick.8)
utilities. 

**More information may be found at [WireGuard.com](https://www.wireguard.com/).**

this derivation enables secret key protection by secure element.

wireguard-tools-se initiates NXP SE050 secure element
private key generation and emits public key corresponds.

This utilizes Platform SCP03 encryption between Raspberry Pi and NXP SE050,  
note that the AES keys that protect I2C transfer are NXP factory default value.
Please consider rotate SCP03 keys.

## Environment

Raspberry Pi 3B+ or derivatives

NXP SE050, especially the variants that can handle Curve25519. [See NXP datasheet.](https://www.nxp.jp/docs/en/application-note/AN12436.pdf)
You can get for [Plug & Trust Click NXP SE050](https://www.mikroe.com/plugtrust-click) as off the shelf.
This product comes with SE050C2 variant that can handle Curve25519.

The variant should keep noted that corresponds for the use of key selection on config.

Raspberry Pi OS Bullseye 5.15.84-v7+

## Prepare

git clone --recursive 
Enable I2C on sudo raspi-config

make sure I2C communication as follows:

```
$ i2cdetect -y 1
     0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
00:                         -- -- -- -- -- -- -- --
10: -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
20: -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
30: -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
40: -- -- -- -- -- -- -- -- 48 -- -- -- -- -- -- --
50: -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
60: -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
70: -- -- -- -- -- -- -- --
```

select the SE050 PlatformSCP03 key variants on the code as follows in src/fsl_sss_ftr.h
The example shows SE050C2 variant selected.

```
/* Enable one of these
 * If none is selected, default config would be used
 */
#define SSS_PFSCP_ENABLE_SE050A1 0
#define SSS_PFSCP_ENABLE_SE050A2 0
#define SSS_PFSCP_ENABLE_SE050B1 0
#define SSS_PFSCP_ENABLE_SE050B2 0
#define SSS_PFSCP_ENABLE_SE050C1 0
#define SSS_PFSCP_ENABLE_SE050C2 1
#define SSS_PFSCP_ENABLE_SE050_DEVKIT 0
#define SSS_PFSCP_ENABLE_SE051A2 0
#define SSS_PFSCP_ENABLE_SE051C2 0
#define SSS_PFSCP_ENABLE_SE050F2 0
#define SSS_PFSCP_ENABLE_SE051C_0005A8FA 0
#define SSS_PFSCP_ENABLE_SE051A_0001A920 0
#define SSS_PFSCP_ENABLE_SE050E_0001A921 0
#define SSS_PFSCP_ENABLE_A5000_0004A736 0
#define SSS_PFSCP_ENABLE_SE050F2_0001A92A 0
#define SSS_PFSCP_ENABLE_OTHER 0
```

## Building

    $ cd src
    $ make

There are no dependencies other than a good C compiler and a sane libc.

## Installing

    # make install

## Using

There is a modification for wg genkey.
It changes the secret key contents of struct member into key symbol number to hide private key.

    # wg genkey 0x10000005
    # BQAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=

Key symbol number stands for 8-digits hex number as NXP SE050 key object rules.
Public key generation needs also key symbol number that emits by wg genkey.

    # wg genkey 0x10000005 | wg pubkey
    # dF/c0F2KtFLVtoUXzgsvGCCXBf2ue3fiQ8cmJDsAY2s=

The public key can use as same as normal version of wireguard on counterpart node.

This wireguard-tools version requires secure element enabled version of [wireguard kernel module](https://github.com/kmwebnet/wireguard-se).

## License

This project is released under the [GPLv2](COPYING).
