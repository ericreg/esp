// SPDX-License-Identifier: GPL-2.0-or-later
/* ESP virtual monitor. Userspace owns encoding, authentication and networking. */
#include <linux/module.h>
#include <linux/version.h>
#include <linux/compat.h>
#include <linux/miscdevice.h>
#include <linux/platform_device.h>
#include <linux/poll.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <drm/clients/drm_client_setup.h>
#include <drm/drm_fbdev_shmem.h>
#include <drm/drm_atomic.h>
#include <drm/drm_atomic_helper.h>
#include <drm/drm_atomic_state_helper.h>
#include <drm/drm_connector.h>
#include <drm/drm_drv.h>
#include <drm/drm_vblank.h>
#include <drm/drm_edid.h>
#include <drm/drm_fourcc.h>
#include <drm/drm_framebuffer.h>
#include <drm/drm_gem_atomic_helper.h>
#include <drm/drm_gem_framebuffer_helper.h>
#include <drm/drm_gem_shmem_helper.h>
#include <drm/drm_managed.h>
#include <drm/drm_modeset_helper_vtables.h>
#include <drm/drm_probe_helper.h>
#include "esp_video.h"

struct esp_device {
	struct drm_device drm;
	struct drm_plane plane;
	struct drm_crtc crtc;
	struct drm_encoder encoder;
	struct drm_connector connector;
	struct miscdevice misc;
	struct mutex lock;
	wait_queue_head_t wait;
	atomic_t owner;
	bool connected;
	u32 width, height;
	u64 sequence, consumed;
	u8 *pixels;
	size_t bytes;
};

/* DRM renamed the commit-state type in the 7.x API. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(7, 2, 0)
#define esp_atomic_state drm_atomic_commit
#else
#define esp_atomic_state drm_atomic_state
#endif
static struct platform_device *esp_platform;

static enum drm_connector_status esp_detect(struct drm_connector *connector, bool force)
{
	struct esp_device *esp = container_of(connector, struct esp_device, connector);
	return READ_ONCE(esp->connected) ? connector_status_connected : connector_status_disconnected;
}

static int esp_modes(struct drm_connector *connector)
{
	struct esp_device *esp = container_of(connector, struct esp_device, connector);
	struct drm_display_mode *mode;
	u32 w, h;
	mutex_lock(&esp->lock);
	w = esp->width;
	h = esp->height;
	mutex_unlock(&esp->lock);
	if (!w || !h)
		return 0;
	mode = drm_cvt_mode(&esp->drm, w, h, 60, false, false, false);
	if (!mode)
		return 0;
	/* CVT rounds horizontal active pixels to multiples of eight. A virtual
	 * output must preserve the requested size, including 1366-pixel panels. */
	mode->hdisplay = w;
	mode->vdisplay = h;
	drm_mode_set_name(mode);
	mode->type |= DRM_MODE_TYPE_PREFERRED;
	drm_mode_probed_add(connector, mode);
	return 1;
}

static const struct drm_connector_funcs esp_connector_funcs = {
	.reset = drm_atomic_helper_connector_reset,
	.detect = esp_detect,
	.fill_modes = drm_helper_probe_single_connector_modes,
	.destroy = drm_connector_cleanup,
	.atomic_duplicate_state = drm_atomic_helper_connector_duplicate_state,
	.atomic_destroy_state = drm_atomic_helper_connector_destroy_state,
};
static const struct drm_connector_helper_funcs esp_connector_helpers = {
	.get_modes = esp_modes,
};

static int esp_plane_check(struct drm_plane *plane, struct esp_atomic_state *state)
{
	struct drm_plane_state *new = drm_atomic_get_new_plane_state(state, plane);
	struct drm_crtc_state *crtc;
	if (!new->crtc)
		return 0;
	crtc = drm_atomic_get_new_crtc_state(state, new->crtc);
	if (!crtc)
		return -EINVAL;
	if (IS_ERR(crtc))
		return PTR_ERR(crtc);
	crtc->no_vblank = true;
	return drm_atomic_helper_check_plane_state(new, crtc,
		DRM_PLANE_NO_SCALING, DRM_PLANE_NO_SCALING, false, true);
}

static void esp_plane_update(struct drm_plane *plane, struct esp_atomic_state *state)
{
	struct esp_device *esp = container_of(plane, struct esp_device, plane);
	struct drm_plane_state *new = drm_atomic_get_new_plane_state(state, plane);
	struct drm_shadow_plane_state *shadow = to_drm_shadow_plane_state(new);
	struct drm_framebuffer *fb = new->fb;
	u32 y;
	if (!fb || !new->visible)
		return;
	mutex_lock(&esp->lock);
	if (esp->connected && esp->pixels && new->src_w == (esp->width << 16) &&
	    new->src_h == (esp->height << 16) && !(new->src_x & 0xffff) &&
	    !(new->src_y & 0xffff)) {
		for (y = 0; y < esp->height; y++)
			iosys_map_memcpy_from(esp->pixels + y * esp->width * 4,
				&shadow->data[0], ((size_t)y + (new->src_y >> 16)) *
				fb->pitches[0] + (new->src_x >> 16) * 4, esp->width * 4);
		esp->sequence++;
	}
	mutex_unlock(&esp->lock);
	wake_up_interruptible(&esp->wait);
}

static void esp_plane_disable(struct drm_plane *plane, struct esp_atomic_state *state)
{
	struct esp_device *esp = container_of(plane, struct esp_device, plane);
	mutex_lock(&esp->lock);
	if (esp->pixels) {
		memset(esp->pixels, 0, esp->bytes);
		esp->sequence++;
	}
	mutex_unlock(&esp->lock);
	wake_up_interruptible(&esp->wait);
}
static const struct drm_plane_funcs esp_plane_funcs = {
	.update_plane = drm_atomic_helper_update_plane,
	.disable_plane = drm_atomic_helper_disable_plane,
	.destroy = drm_plane_cleanup,
	DRM_GEM_SHADOW_PLANE_FUNCS,
};
static const struct drm_plane_helper_funcs esp_plane_helpers = {
	.atomic_check = esp_plane_check,
	.atomic_update = esp_plane_update,
	.atomic_disable = esp_plane_disable,
	DRM_GEM_SHADOW_PLANE_HELPER_FUNCS,
};
static void esp_crtc_flush(struct drm_crtc *crtc, struct esp_atomic_state *state)
{
	struct drm_pending_vblank_event *event = crtc->state->event;
	if (event) {
		crtc->state->event = NULL;
		spin_lock_irq(&crtc->dev->event_lock);
		drm_crtc_send_vblank_event(crtc, event);
		spin_unlock_irq(&crtc->dev->event_lock);
	}
}
static const struct drm_crtc_funcs esp_crtc_funcs = {
	.set_config = drm_atomic_helper_set_config,
	.page_flip = drm_atomic_helper_page_flip,
	.destroy = drm_crtc_cleanup,
	.reset = drm_atomic_helper_crtc_reset,
	.atomic_duplicate_state = drm_atomic_helper_crtc_duplicate_state,
	.atomic_destroy_state = drm_atomic_helper_crtc_destroy_state,
};
static const struct drm_crtc_helper_funcs esp_crtc_helpers = {
	.atomic_flush = esp_crtc_flush,
};
static const struct drm_encoder_funcs esp_encoder_funcs = {
	.destroy = drm_encoder_cleanup,
};
static const struct drm_mode_config_funcs esp_mode_config_funcs = {
	.fb_create = drm_gem_fb_create_with_dirty,
	.atomic_check = drm_atomic_helper_check,
	.atomic_commit = drm_atomic_helper_commit,
};
static const struct drm_mode_config_helper_funcs esp_mode_config_helpers = {
	.atomic_commit_tail = drm_atomic_helper_commit_tail,
};
DEFINE_DRM_GEM_FOPS(esp_drm_fops);
static const struct drm_driver esp_drm_driver = {
	.driver_features = DRIVER_GEM | DRIVER_MODESET | DRIVER_ATOMIC,
	.fops = &esp_drm_fops,
	DRM_GEM_SHMEM_DRIVER_OPS,
	DRM_FBDEV_SHMEM_DRIVER_OPS,
	.name = "esp_video", .desc = "ESP virtual display",
	.major = 1, .minor = 0,
};

static int esp_open(struct inode *inode, struct file *file)
{
	struct esp_device *esp = container_of(file->private_data, struct esp_device, misc);
	if (atomic_cmpxchg(&esp->owner, 0, 1))
		return -EBUSY;
	drm_dev_get(&esp->drm);
	file->private_data = esp;
	return 0;
}
static long esp_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct esp_device *esp = file->private_data;
	struct esp_video_mode mode;
	u8 *pixels;
	size_t bytes;
	if (cmd != ESP_VIDEO_CONNECT)
		return -ENOTTY;
	if (copy_from_user(&mode, (void __user *)arg, sizeof(mode)))
		return -EFAULT;
	if (mode.width < 2 || mode.height < 2 || mode.width > ESP_VIDEO_MAX_AXIS ||
	    mode.height > ESP_VIDEO_MAX_AXIS || (mode.width & 1) || (mode.height & 1) ||
	    mode.width * mode.height > ESP_VIDEO_MAX_PIXELS)
		return -EINVAL;
	bytes = (size_t)mode.width * mode.height * 4;
	pixels = vzalloc(bytes);
	if (!pixels)
		return -ENOMEM;
	mutex_lock(&esp->lock);
	if (esp->connected) {
		mutex_unlock(&esp->lock);
		vfree(pixels);
		return -EBUSY;
	}
	esp->pixels = pixels;
	esp->bytes = bytes;
	esp->width = mode.width;
	esp->height = mode.height;
	esp->sequence = esp->consumed = 0;
	WRITE_ONCE(esp->connected, true);
	mutex_unlock(&esp->lock);
	drm_kms_helper_hotplug_event(&esp->drm);
	return 0;
}
static ssize_t esp_read(struct file *file, char __user *buf, size_t count, loff_t *offset)
{
	struct esp_device *esp = file->private_data;
	struct esp_video_frame header;
	int ret;
	if (file->f_flags & O_NONBLOCK) {
		if (READ_ONCE(esp->sequence) == READ_ONCE(esp->consumed))
			return -EAGAIN;
	} else {
		ret = wait_event_interruptible(esp->wait,
			READ_ONCE(esp->sequence) != READ_ONCE(esp->consumed) ||
			!READ_ONCE(esp->connected));
		if (ret)
			return ret;
	}
	mutex_lock(&esp->lock);
	if (!esp->connected) { ret = -ENODEV; goto out; }
	header = (struct esp_video_frame) { ESP_VIDEO_ABI, esp->width, esp->height,
		esp->bytes, esp->sequence };
	if (count < sizeof(header) + esp->bytes) { ret = -EMSGSIZE; goto out; }
	if (copy_to_user(buf, &header, sizeof(header)) ||
	    copy_to_user(buf + sizeof(header), esp->pixels, esp->bytes)) {
		ret = -EFAULT; goto out;
	}
	esp->consumed = esp->sequence;
	ret = sizeof(header) + esp->bytes;
out:
	mutex_unlock(&esp->lock);
	return ret;
}
static __poll_t esp_poll(struct file *file, poll_table *wait)
{
	struct esp_device *esp = file->private_data;
	poll_wait(file, &esp->wait, wait);
	if (!READ_ONCE(esp->connected))
		return EPOLLHUP;
	if (READ_ONCE(esp->sequence) != READ_ONCE(esp->consumed))
		return EPOLLIN | EPOLLRDNORM;
	return 0;
}
static int esp_release(struct inode *inode, struct file *file)
{
	struct esp_device *esp = file->private_data;
	mutex_lock(&esp->lock);
	WRITE_ONCE(esp->connected, false);
	vfree(esp->pixels);
	esp->pixels = NULL;
	esp->bytes = 0;
	esp->width = esp->height = 0;
	mutex_unlock(&esp->lock);
	drm_kms_helper_hotplug_event(&esp->drm);
	atomic_set(&esp->owner, 0);
	wake_up_interruptible(&esp->wait);
	drm_dev_put(&esp->drm);
	return 0;
}
static const struct file_operations esp_capture_fops = {
	.owner = THIS_MODULE, .open = esp_open, .release = esp_release,
	.read = esp_read, .poll = esp_poll, .unlocked_ioctl = esp_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = compat_ptr_ioctl,
#endif

};
static int esp_probe(struct platform_device *pdev)
{
	static const u32 formats[] = { DRM_FORMAT_XRGB8888 };
	static const u64 modifiers[] = { DRM_FORMAT_MOD_LINEAR, DRM_FORMAT_MOD_INVALID };
	struct esp_device *esp;
	struct drm_device *drm;
	int ret;
	esp = devm_drm_dev_alloc(&pdev->dev, &esp_drm_driver, struct esp_device, drm);
	if (IS_ERR(esp)) return PTR_ERR(esp);
	drm = &esp->drm;
	mutex_init(&esp->lock);
	init_waitqueue_head(&esp->wait);
	atomic_set(&esp->owner, 0);
	ret = drmm_mode_config_init(drm);
	if (ret) return ret;
	drm->mode_config.min_width = drm->mode_config.min_height = 2;
	drm->mode_config.max_width = drm->mode_config.max_height = ESP_VIDEO_MAX_AXIS;
	drm->mode_config.funcs = &esp_mode_config_funcs;
	drm->mode_config.helper_private = &esp_mode_config_helpers;
	ret = drm_universal_plane_init(drm, &esp->plane, 1, &esp_plane_funcs,
		formats, ARRAY_SIZE(formats), modifiers, DRM_PLANE_TYPE_PRIMARY, NULL);
	if (ret) return ret;
	drm_plane_helper_add(&esp->plane, &esp_plane_helpers);
	ret = drm_crtc_init_with_planes(drm, &esp->crtc, &esp->plane, NULL, &esp_crtc_funcs, NULL);
	if (ret) return ret;
	drm_crtc_helper_add(&esp->crtc, &esp_crtc_helpers);
	ret = drm_encoder_init(drm, &esp->encoder, &esp_encoder_funcs, DRM_MODE_ENCODER_VIRTUAL, NULL);
	if (ret) return ret;
	esp->encoder.possible_crtcs = 1;
	ret = drm_connector_init(drm, &esp->connector, &esp_connector_funcs, DRM_MODE_CONNECTOR_VIRTUAL);
	if (ret) return ret;
	drm_connector_helper_add(&esp->connector, &esp_connector_helpers);
	ret = drm_connector_attach_encoder(&esp->connector, &esp->encoder);
	if (ret) return ret;
	drm_mode_config_reset(drm);
	ret = drm_dev_register(drm, 0);
	if (ret) return ret;
	esp->misc = (struct miscdevice) { .minor = MISC_DYNAMIC_MINOR,
		.name = "esp-video", .fops = &esp_capture_fops, .mode = 0600 };
	ret = misc_register(&esp->misc);
	if (ret) { drm_dev_unregister(drm); return ret; }
	drm_client_setup_with_fourcc(drm, DRM_FORMAT_XRGB8888);
	platform_set_drvdata(pdev, esp);
	return 0;
}
static void esp_remove(struct platform_device *pdev)
{
	struct esp_device *esp = platform_get_drvdata(pdev);
	misc_deregister(&esp->misc);
	drm_dev_unplug(&esp->drm);
	drm_atomic_helper_shutdown(&esp->drm);
}
static struct platform_driver esp_platform_driver = {
	.probe = esp_probe, .remove = esp_remove,
	.driver = { .name = "esp-video" },
};
static int __init esp_init(void)
{
	int ret = platform_driver_register(&esp_platform_driver);
	if (ret) return ret;
	esp_platform = platform_device_register_simple("esp-video", -1, NULL, 0);
	if (IS_ERR(esp_platform)) {
		platform_driver_unregister(&esp_platform_driver);
		return PTR_ERR(esp_platform);
	}
	return 0;
}
static void __exit esp_exit(void)
{
	platform_device_unregister(esp_platform);
	platform_driver_unregister(&esp_platform_driver);
}
module_init(esp_init);
module_exit(esp_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("ESP single virtual video output");
