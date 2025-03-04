#!/bin/bash
# Check if the script is run as root

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

run_dir=$(readlink -f $(pwd))

# Check if a device argument is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <device>"
    exit 1
fi

device=$1

# Verify that the device exists
if [ ! -b "$device" ]; then
    echo "Error: Device $device does not exist."
    exit 1
fi

# Load dedup module once
sudo insmod ../dedup.ko

# Get the size of the device in 512-byte sectors
device_size=$(blockdev --getsize64 "$device")
# Convert to 4096-byte blocks (or whatever block size your dedup module uses)
num_blocks=$((device_size / 4096))

# Create the device-mapper for deduplication
echo "0 $num_blocks dedup $device 4096" | sudo dmsetup create dedup

for dir in "$run_dir"/*; do
    if [ -d "$dir" ]; then
        for test_script in "$dir"/*.sh; do
            if [ -x "$test_script" ]; then
                echo "$dir"
                "$test_script" "$dir"
            fi
        done
        echo ""
    fi
done

# Final cleanup
sudo dmsetup remove dedup
sudo rmmod dedup
