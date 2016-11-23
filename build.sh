#!/bin/bash

module add raspberry
KERNEL=kernel7
make -j8 ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- zImage modules dtbs
