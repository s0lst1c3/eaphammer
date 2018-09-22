LOCAL_PATH:=$(call my-dir)

HCX_CFLAGS:=-std=gnu99 -O3 -Wall -Wextra

include $(CLEAR_VARS)
LOCAL_MODULE			:= hcxdumptool
LOCAL_CFLAGS			+= $(HCX_CFLAGS)
LOCAL_SRC_FILES			:= hcxdumptool.c
include $(BUILD_EXECUTABLE)
