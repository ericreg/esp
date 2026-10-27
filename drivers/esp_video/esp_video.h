/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef ESP_VIDEO_UAPI_H
#define ESP_VIDEO_UAPI_H
#include <linux/ioctl.h>
#include <linux/types.h>

/* Native-endian local ABI; never sent over the network. */
#define ESP_VIDEO_ABI 1
#define ESP_VIDEO_MAX_AXIS 4096
#define ESP_VIDEO_MAX_PIXELS 16000000
struct esp_video_mode { __u32 width; __u32 height; };
#define ESP_VIDEO_CONNECT _IOW('E', 1, struct esp_video_mode)
/* Each read returns one header followed by tightly packed XRGB8888 pixels. */
struct esp_video_frame {
	__u32 version;
	__u32 width;
	__u32 height;
	__u32 bytes;
	__u64 sequence;
};
/* Snapshot a readable /dev/fbN while excluding fbcon redraw/VT switches.
 * Pixel memory is tightly packed, native little-endian RGB; convert after unlock.
 * Does not serialize arbitrary userspace mmap writers. Requires CAP_SYS_ADMIN.
 * Fixed-width fields keep this ioctl identical for native and compat processes. */
struct esp_video_console_snapshot {
    __u64 pixels;
    __u32 capacity, fb_fd, vt;
    __u32 width, height, bytes_per_pixel;
    __u32 red_offset, red_length, green_offset, green_length, blue_offset, blue_length;
    __u32 reserved[2];
};
#define ESP_VIDEO_CONSOLE_SNAPSHOT _IOWR('E', 2, struct esp_video_console_snapshot)
#endif
