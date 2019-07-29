#!/usr/bin/env bash

# https://github.com/MaskRay/ccls/wiki/Build

set -eu

git clone https://git.llvm.org/git/llvm.git
git clone https://git.llvm.org/git/clang.git llvm/tools/clang
(
cd llvm
cmake \
	-H. \
	-BRelease \
	-G Ninja \
	-DCMAKE_BUILD_TYPE=Release \
	-DBUILD_SHARED_LIBS=ON \
	-DLLVM_ENABLE_LLD=ON \
	-DLLVM_TARGETS_TO_BUILD=X86
ninja -C Release clang clangFormat clangFrontendTool clangIndex clangTooling cxx
)

git clone --depth=1 --recursive https://github.com/MaskRay/ccls
(
cd ccls
cmake \
	-H. \
	-BRelease \
	-G Ninja \
	-DCMAKE_BUILD_TYPE=Release \
	-DCMAKE_CXX_COMPILER=clang++ \
	-DCMAKE_EXE_LINKER_FLAGS=-fuse-ld=lld \
	-DCMAKE_PREFIX_PATH="$HOME/llvm/Release;$HOME/llvm/Release/tools/clang;$HOME/llvm;$HOME/llvm/tools/clang"
ninja -C Release
)
