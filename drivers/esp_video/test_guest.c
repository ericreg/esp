// SPDX-License-Identifier: GPL-2.0-or-later
/* Runs only as PID 1 in an isolated VM. Never run against the host's DRM devices. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <drm.h>
#include <drm_mode.h>
#include "esp_video.h"

static void fail(const char *message) {
	perror(message);
	puts("ESP_DRIVER_TEST_FAILED");
	fflush(stdout);
	reboot(RB_POWER_OFF);
	_exit(1);
}
#define CHECK(expr) do { if (!(expr)) fail(#expr); } while (0)
static uintptr_t ptr(void *p) { return (uintptr_t)p; }
static uint32_t pattern(unsigned x, unsigned y) {
	return ((x * 255 / 320) << 16) | ((y * 255 / 240) << 8) | 0x33;
}
int main(void) {
	int module, card, capture, console, pipefd[2];
	struct drm_mode_card_res resources = {0};
	struct drm_mode_get_connector connector = {0};
	struct drm_mode_modeinfo modes[16] = {0};
	uint32_t connectors[16], crtcs[16], encoders[16], properties[32];
	uint64_t values[32];
	struct drm_mode_create_dumb dumb = { .width = 320, .height = 240, .bpp = 32 };
	struct drm_mode_map_dumb mapping = {0};
	struct drm_mode_fb_cmd fb = { .width = 320, .height = 240, .bpp = 32, .depth = 24 };
	struct drm_mode_crtc crtc = {0};
	struct esp_video_mode mode = {320, 240};
	struct pollfd pollfd;
	uint8_t *pixels, *frame;
	pid_t child;
	unsigned x, y;
	if (getpid() != 1) { fputs("This test must run as VM init.\n", stderr); return 2; }
	mkdir("/dev", 0755); mkdir("/proc", 0755); mkdir("/sys", 0755);
	mount("devtmpfs", "/dev", "devtmpfs", 0, NULL);
	mount("proc", "/proc", "proc", 0, NULL);
	mount("sysfs", "/sys", "sysfs", 0, NULL);
	console = open("/dev/console", O_RDWR);
	if (console >= 0) { dup2(console, 0); dup2(console, 1); dup2(console, 2); }
	setbuf(stdout, NULL);
	puts("ESP driver isolated guest test starting");
	module = open("/esp_video.ko", O_RDONLY); CHECK(module >= 0);
	CHECK(syscall(SYS_finit_module, module, "", 0) == 0); close(module);
	capture = open("/dev/esp-video", O_RDWR | O_NONBLOCK); CHECK(capture >= 0);
	CHECK(open("/dev/esp-video", O_RDWR) == -1 && errno == EBUSY);
	struct esp_video_mode invalid[] = { {0, 240}, {3, 240}, {4097, 2}, {4096, 4096} };
	for (unsigned i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++)
		CHECK(ioctl(capture, ESP_VIDEO_CONNECT, &invalid[i]) == -1 && errno == EINVAL);
	CHECK(ioctl(capture, ESP_VIDEO_CONNECT, &mode) == 0);
	card = open("/dev/dri/card0", O_RDWR); CHECK(card >= 0);
	CHECK(ioctl(card, DRM_IOCTL_SET_MASTER, 0) == 0);
	CHECK(ioctl(card, DRM_IOCTL_MODE_GETRESOURCES, &resources) == 0);
	CHECK(resources.count_connectors == 1 && resources.count_crtcs == 1 && resources.count_encoders == 1);
	resources.connector_id_ptr = ptr(connectors); resources.crtc_id_ptr = ptr(crtcs);
	resources.encoder_id_ptr = ptr(encoders);
	CHECK(ioctl(card, DRM_IOCTL_MODE_GETRESOURCES, &resources) == 0);
	connector.connector_id = connectors[0];
	CHECK(ioctl(card, DRM_IOCTL_MODE_GETCONNECTOR, &connector) == 0);
	CHECK(connector.connection == 1 && connector.count_modes > 0 && connector.count_modes <= 16);
	CHECK(connector.count_props <= 32 && connector.count_encoders <= 16);
	connector.props_ptr = ptr(properties); connector.prop_values_ptr = ptr(values);
	connector.encoders_ptr = ptr(encoders);
	connector.modes_ptr = ptr(modes);
	CHECK(ioctl(card, DRM_IOCTL_MODE_GETCONNECTOR, &connector) == 0);
	CHECK(modes[0].hdisplay == 320 && modes[0].vdisplay == 240);
	CHECK(ioctl(card, DRM_IOCTL_MODE_CREATE_DUMB, &dumb) == 0);
	mapping.handle = dumb.handle;
	CHECK(ioctl(card, DRM_IOCTL_MODE_MAP_DUMB, &mapping) == 0);
	pixels = mmap(NULL, dumb.size, PROT_READ | PROT_WRITE, MAP_SHARED, card, mapping.offset);
	CHECK(pixels != MAP_FAILED);
	for (y = 0; y < 240; y++) for (x = 0; x < 320; x++)
		*(uint32_t *)(pixels + y * dumb.pitch + x * 4) = pattern(x, y);
	fb.pitch = dumb.pitch; fb.handle = dumb.handle;
	CHECK(ioctl(card, DRM_IOCTL_MODE_ADDFB, &fb) == 0);
	crtc.crtc_id = crtcs[0]; crtc.fb_id = fb.fb_id;
	crtc.set_connectors_ptr = ptr(connectors); crtc.count_connectors = 1;
	crtc.mode = modes[0]; crtc.mode_valid = 1;
	CHECK(ioctl(card, DRM_IOCTL_MODE_SETCRTC, &crtc) == 0);
	pollfd = (struct pollfd) { .fd = capture, .events = POLLIN };
	CHECK(poll(&pollfd, 1, 3000) == 1 && pollfd.revents & POLLIN);
	frame = malloc(24 + 320 * 240 * 4); CHECK(frame);
	CHECK(read(capture, frame, 24) == -1 && errno == EMSGSIZE);
	CHECK(read(capture, frame, 24 + 320 * 240 * 4) == 24 + 320 * 240 * 4);
	CHECK(((struct esp_video_frame *)frame)->version == 1);
	CHECK(((struct esp_video_frame *)frame)->bytes == 320 * 240 * 4);
	for (y = 0; y < 240; y++) for (x = 0; x < 320; x++)
		CHECK(*(uint32_t *)(frame + 24 + (y * 320 + x) * 4) == pattern(x, y));
	CHECK(read(capture, frame, 24 + 320 * 240 * 4) == -1 && errno == EAGAIN);
	puts("Driver pixels, framing, exclusive owner, and nonblocking read passed");
	/* Exercise updates and old/new shadow-buffer lifetime over repeated commits. */
	for (unsigned iteration = 0; iteration < 20; iteration++) {
		struct drm_mode_create_dumb next = { .width = 320, .height = 240, .bpp = 32 };
		struct drm_mode_map_dumb next_map = {0};
		struct drm_mode_fb_cmd next_fb = { .width = 320, .height = 240, .bpp = 32, .depth = 24 };
		uint8_t *next_pixels;
		uint32_t expected = 0x102030 + iteration;
		CHECK(ioctl(card, DRM_IOCTL_MODE_CREATE_DUMB, &next) == 0);
		next_map.handle = next.handle;
		CHECK(ioctl(card, DRM_IOCTL_MODE_MAP_DUMB, &next_map) == 0);
		next_pixels = mmap(NULL, next.size, PROT_READ | PROT_WRITE, MAP_SHARED, card, next_map.offset);
		CHECK(next_pixels != MAP_FAILED);
		for (y = 0; y < 240; y++) for (x = 0; x < 320; x++)
			*(uint32_t *)(next_pixels + y * next.pitch + x * 4) = expected;
		next_fb.pitch = next.pitch; next_fb.handle = next.handle;
		CHECK(ioctl(card, DRM_IOCTL_MODE_ADDFB, &next_fb) == 0);
		crtc.fb_id = next_fb.fb_id;
		CHECK(ioctl(card, DRM_IOCTL_MODE_SETCRTC, &crtc) == 0);
		CHECK(poll(&pollfd, 1, 3000) == 1 && pollfd.revents & POLLIN);
		CHECK(read(capture, frame, 24 + 320 * 240 * 4) == 24 + 320 * 240 * 4);
		for (y = 0; y < 240; y++) for (x = 0; x < 320; x++)
			CHECK(*(uint32_t *)(frame + 24 + (y * 320 + x) * 4) == expected);
		munmap(next_pixels, next.size);
	}
	puts("Repeated scanout updates passed");
	/* A compositor may scan out a cropped region of a wider framebuffer. */
	struct drm_mode_create_dumb wide = { .width = 640, .height = 240, .bpp = 32 };
	struct drm_mode_map_dumb wide_map = {0};
	struct drm_mode_fb_cmd wide_fb = { .width = 640, .height = 240, .bpp = 32, .depth = 24 };
	CHECK(ioctl(card, DRM_IOCTL_MODE_CREATE_DUMB, &wide) == 0);
	wide_map.handle = wide.handle;
	CHECK(ioctl(card, DRM_IOCTL_MODE_MAP_DUMB, &wide_map) == 0);
	uint8_t *wide_pixels = mmap(NULL, wide.size, PROT_READ | PROT_WRITE, MAP_SHARED, card, wide_map.offset);
	CHECK(wide_pixels != MAP_FAILED);
	for (y = 0; y < 240; y++) for (x = 0; x < 640; x++)
		*(uint32_t *)(wide_pixels + y * wide.pitch + x * 4) = x < 320 ? 0xabcdef : 0x123456;
	wide_fb.pitch = wide.pitch; wide_fb.handle = wide.handle;
	CHECK(ioctl(card, DRM_IOCTL_MODE_ADDFB, &wide_fb) == 0);
	crtc.fb_id = wide_fb.fb_id; crtc.x = 320;
	CHECK(ioctl(card, DRM_IOCTL_MODE_SETCRTC, &crtc) == 0);
	CHECK(poll(&pollfd, 1, 3000) == 1 && pollfd.revents & POLLIN);
	CHECK(read(capture, frame, 24 + 320 * 240 * 4) == 24 + 320 * 240 * 4);
	for (y = 0; y < 240; y++) for (x = 0; x < 320; x++)
		CHECK(*(uint32_t *)(frame + 24 + (y * 320 + x) * 4) == 0x123456);
	munmap(wide_pixels, wide.size);
	puts("Cropped scanout passed");
	close(capture);
	connector.count_modes = 0;
	CHECK(ioctl(card, DRM_IOCTL_MODE_GETCONNECTOR, &connector) == 0 && connector.connection == 2);
	CHECK(pipe(pipefd) == 0);
	child = fork(); CHECK(child >= 0);
	if (!child) {
		close(pipefd[0]);
		capture = open("/dev/esp-video", O_RDWR); CHECK(capture >= 0);
		CHECK(ioctl(capture, ESP_VIDEO_CONNECT, &mode) == 0);
		CHECK(write(pipefd[1], "1", 1) == 1);
		for (;;) pause();
	}
	close(pipefd[1]); CHECK(read(pipefd[0], frame, 1) == 1);
	CHECK(kill(child, SIGKILL) == 0); CHECK(waitpid(child, NULL, 0) == child);
	connector.count_modes = 0;
	CHECK(ioctl(card, DRM_IOCTL_MODE_GETCONNECTOR, &connector) == 0 && connector.connection == 2);
	/* CVT's eight-pixel rounding must not change an actual source's width. */
	capture = open("/dev/esp-video", O_RDWR); CHECK(capture >= 0);
	mode = (struct esp_video_mode) {1366, 768};
	CHECK(ioctl(capture, ESP_VIDEO_CONNECT, &mode) == 0);
	connector.count_modes = 0;
	CHECK(ioctl(card, DRM_IOCTL_MODE_GETCONNECTOR, &connector) == 0);
	CHECK(connector.count_modes == 1);
	CHECK(ioctl(card, DRM_IOCTL_MODE_GETCONNECTOR, &connector) == 0);
	CHECK(modes[0].hdisplay == 1366 && modes[0].vdisplay == 768);
	close(capture);
	munmap(pixels, dumb.size); close(card); free(frame);
	CHECK(syscall(SYS_delete_module, "esp_video", O_NONBLOCK) == 0);
	puts("ESP_DRIVER_TEST_PASSED");
	reboot(RB_POWER_OFF); return 0;
}
