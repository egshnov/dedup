# dedup (WIP)

Device-mapper driver module for Linux kernel that implements deduplication.

## Current status

Inram deduplication.

Rb-tree for hash->pbn and lbn->pbn mappings

Xxhash64 hash function (collision resolving currenly not supported)


## Kernel version

Driver was tested on Linux kernel version 6.10.14

## Build

Run `make` form the repo's directory.

## Load

Run `sudo insmod dedup.ko`.
You will see `dedup` appear in `lsmod`.

## Adding device

run `sudo echo 0 20000 dedup /dev/name_of_the_underlying_device 0|sudo dmsetup create <name of the new device>`   

run 'sudo dmsetup ls' and `lsblk` to check that dedup instantiated correctly

## Usage 
`sudo dd if=input of=/dev/mapper/dedup oflag=direct bs=4K count=128` — copy from input file to underlying device  

`sudo dd of=output if=/dev/blkm1 iflag=direct bs=4K count=128` —  copy from underlying device to ouput file

