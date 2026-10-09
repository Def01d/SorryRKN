#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
sdk_path="${GRAYBRIDGE_SDK:-${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}}"
if [[ -z "$sdk_path" && -f local.properties ]]; then
  sdk_path="$(sed -n 's/^sdk.dir=//p' local.properties)"
fi
: "${sdk_path:?Set ANDROID_HOME to your Android SDK}"
ndk_path="$sdk_path/ndk/28.2.13676358"
"$ndk_path/ndk-build" -B -j4 REV_ID=graybridge-0.3.0 NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=native/Android.mk \
  NDK_APPLICATION_MK=native/Application.mk NDK_OUT=build/native/obj \
  NDK_LIBS_OUT=app/src/main/jniLibs APP_MODULES='graybridge hev-socks5-tunnel'
case "$(uname -s)" in
  Darwin) host_tag=darwin-x86_64;;
  *) host_tag=linux-x86_64;;
esac
compiler_path="$ndk_path/toolchains/llvm/prebuilt/$host_tag/bin"
for abi in arm64-v8a x86_64; do
  case "$abi" in
    arm64-v8a) target=aarch64-linux-android26;;
    x86_64) target=x86_64-linux-android26;;
  esac
  "$compiler_path/$target-clang" -std=gnu99 -Os -fPIE -pie -ffunction-sections -fdata-sections \
    -Wl,--gc-sections -Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384 \
    third_party/tpws/*.c third_party/tpws/andr/*.c -lz -llog \
    -o "app/src/main/jniLibs/$abi/libtpws.so"
  "$compiler_path/llvm-strip" "app/src/main/jniLibs/$abi/libtpws.so"
  "$compiler_path/$target-clang" -std=c99 -D_DEFAULT_SOURCE -O2 -fPIE -pie \
    -ffunction-sections -fdata-sections -Ithird_party/byedpi \
    -Wl,--gc-sections -Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384 \
    third_party/byedpi/main.c third_party/byedpi/packets.c third_party/byedpi/conev.c \
    third_party/byedpi/proxy.c third_party/byedpi/desync.c third_party/byedpi/mpool.c \
    third_party/byedpi/extend.c -o "app/src/main/jniLibs/$abi/libbyedpi.so"
  "$compiler_path/llvm-strip" "app/src/main/jniLibs/$abi/libbyedpi.so"
done
