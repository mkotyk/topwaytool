# topwaytool
Tool for managing Android OS images on TopWay car headunit

This tool is used for creating and extracting "signed" image files for some TopWay headunits.
I've only tested on my Allwinner T8 using firmware images found on xda-developers.

See https://forum.xda-developers.com/t/tutorial-how-to-modify-allwinner-t8-firmware-and-to-be-able-to-apply-it.4054951/

## Requirements
I've only tested on Linux.  The code has minimal dependencies and should only require a basic C compiling
environment.

In order to work with the OS images, you will need to be able to mount them in loopback mode. This also requires Linux.
ie `mount -o loop system.img mnt/system`.

## How to build

`make`

## Commands

- verify - Check the checksum on system.img.  This file is usually in 3x 400M parts and needs to be `cat`ed together.
- update - Updates the checksum on system.img.
- decrypt - "Decrypts" the boot.img or vendor.img files.
- encrypt - "Encrypts" the boot.img or vendor.img files.

This tool, combined with `unpackbootimg` and `mkbootimg` (see android source code) should give a developer nearly
full control over customizing firmware for their headunit.

Credit goes to the authors of cks and dcupdate.py from which this tool was inspired from.

Enjoy!

