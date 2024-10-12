# blkmr

Bio-based block device-mapper driver module for Linux kernel that implements deduplication.

## Kernel version

Driver was made for Linux kernel version 6.9.12

## Build

Run `make` form the repo's directory.

## Load

Run `sudo insmod blkm.ko`.
You will see `blkm` appear in `lsmod`.

## Adding device

After building and inserting module go to `/sys/module/blkm/parameters`

To add underlying device do `echo "<path_to_block_device>" >> device_pipe`.
You will see `bdevm1` appear in `lsblk`.  

To remove underlying device do `echo >> rm_device`.  

## Usage 
`sudo dd if=input of=/dev/blkm1 oflag=direct bs=4K count=128` — copy from input file to underlying device   
`sudo dd of=output if=/dev/blkm1 iflag=direct bs=4K count=128` —  copy from underlying device to ouput file
