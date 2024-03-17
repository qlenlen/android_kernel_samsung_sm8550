#!/bin/bash

mkdir out
mkdir aout

make -j$(nproc) -C $(pwd) O=$(pwd)/out LLVM=1 LLVM_IAS=1 kalama_gki_defconfig
make -j$(nproc) -C $(pwd) O=$(pwd)/out LLVM=1 LLVM_IAS=1

cp out/arch/arm64/boot/Image $(pwd)/aout/Image
