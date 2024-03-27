#!/bin/bash

mkdir out
mkdir aout

KERNEL_DEFCONFIG=kalama_gki_defconfig

CLANG_DIR="/home/tools/clang/17"
export PATH="$CLANG_DIR/bin:$PATH"

echo "**** Kernel defconfig is set to $KERNEL_DEFCONFIG ****"
echo -e "***************************************************"

make -j$(nproc --all) -C $(pwd) O=$(pwd)/out \
					  LLVM=1 \
                      LLVM_IAS=1 \
                      $KERNEL_DEFCONFIG
 
make -j$(nproc --all) -C $(pwd) O=$(pwd)/out \
					  LLVM=1 \
                      LLVM_IAS=1 \

cp out/arch/arm64/boot/Image $(pwd)/aout/Image
