
LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_C_INCLUDES := $(LOCAL_PATH)/../mkbootimg
LOCAL_SRC_FILES := unbootimg.c
LOCAL_STATIC_LIBRARIES := libmincrypt

LOCAL_MODULE := unbootimg

include $(BUILD_HOST_EXECUTABLE)

$(call dist-for-goals,droid,$(LOCAL_BUILT_MODULE))
