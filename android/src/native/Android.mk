BRIDGE_PATH := $(call my-dir)
include $(BRIDGE_PATH)/../third_party/hev-socks5-tunnel/Android.mk
LOCAL_PATH := $(BRIDGE_PATH)
include $(CLEAR_VARS)
LOCAL_MODULE := graybridge
LOCAL_SRC_FILES := bridge.c
LOCAL_C_INCLUDES := $(LOCAL_PATH)/../third_party/hev-socks5-tunnel/include
LOCAL_SHARED_LIBRARIES := hev-socks5-tunnel
LOCAL_LDFLAGS := -Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384
include $(BUILD_SHARED_LIBRARY)
