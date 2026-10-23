/* ESP's small libvpx boundary. No libvpx ABI structs cross into Rust. */
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <vpx/vpx_encoder.h>
#include <vpx/vpx_decoder.h>
#include <vpx/vp8cx.h>
#include <vpx/vp8dx.h>

struct esp_vpx {
    vpx_codec_ctx_t ctx;
    vpx_image_t *image;
    unsigned width, height;
};

void esp_vpx_free(struct esp_vpx *v) {
    if (!v) return;
    vpx_codec_destroy(&v->ctx);
    if (v->image) vpx_img_free(v->image);
    free(v);
}

struct esp_vpx *esp_vpx_encoder(unsigned w, unsigned h, unsigned fps, unsigned kbps) {
    struct esp_vpx *v = calloc(1, sizeof(*v));
    vpx_codec_enc_cfg_t cfg;
    if (!v || vpx_codec_enc_config_default(vpx_codec_vp8_cx(), &cfg, 0)) goto fail;
    v->width = cfg.g_w = w; v->height = cfg.g_h = h;
    cfg.g_timebase.num = 1; cfg.g_timebase.den = fps;
    cfg.g_threads = 2; cfg.g_lag_in_frames = 0;
    cfg.g_error_resilient = VPX_ERROR_RESILIENT_DEFAULT;
    cfg.rc_end_usage = VPX_CBR; cfg.rc_target_bitrate = kbps;
    cfg.rc_dropframe_thresh = 0;
    cfg.kf_mode = VPX_KF_AUTO; cfg.kf_max_dist = fps;
    if (vpx_codec_enc_init(&v->ctx, vpx_codec_vp8_cx(), &cfg, 0)) goto fail;
    if (vpx_codec_control(&v->ctx, VP8E_SET_CPUUSED, 8) ||
        vpx_codec_control(&v->ctx, VP8E_SET_ENABLEAUTOALTREF, 0)) goto fail;
    v->image = vpx_img_alloc(NULL, VPX_IMG_FMT_I420, w, h, 32);
    if (!v->image) goto fail;
    v->image->cs = VPX_CS_BT_601; v->image->range = VPX_CR_STUDIO_RANGE;
    return v;
fail: esp_vpx_free(v); return NULL;
}

int esp_vpx_encode(struct esp_vpx *v, const uint8_t *yuv, int64_t pts, int force,
                   uint8_t *out, size_t capacity, size_t *len, int *key) {
    unsigned p, y;
    const vpx_codec_cx_pkt_t *pkt;
    vpx_codec_iter_t iter = NULL;
    *len = 0; *key = 0;
    for (p = 0; p < 3; p++) {
        unsigned w = p ? v->width / 2 : v->width;
        unsigned h = p ? v->height / 2 : v->height;
        for (y = 0; y < h; y++) {
            memcpy(v->image->planes[p] + y * v->image->stride[p], yuv, w);
            yuv += w;
        }
    }
    if (vpx_codec_encode(&v->ctx, v->image, pts, 1,
                         force ? VPX_EFLAG_FORCE_KF : 0, VPX_DL_REALTIME)) return -1;
    while ((pkt = vpx_codec_get_cx_data(&v->ctx, &iter))) {
        if (pkt->kind != VPX_CODEC_CX_FRAME_PKT) continue;
        if (*len || pkt->data.frame.sz > capacity ||
            pkt->data.frame.flags & (VPX_FRAME_IS_INVISIBLE | VPX_FRAME_IS_FRAGMENT)) return -2;
        memcpy(out, pkt->data.frame.buf, pkt->data.frame.sz);
        *len = pkt->data.frame.sz;
        *key = !!(pkt->data.frame.flags & VPX_FRAME_IS_KEY);
    }
    return 0;
}

struct esp_vpx *esp_vpx_decoder(unsigned w, unsigned h) {
    struct esp_vpx *v = calloc(1, sizeof(*v));
    vpx_codec_dec_cfg_t cfg = { .threads = 2, .w = w, .h = h };
    if (!v) return NULL;
    v->width = w; v->height = h;
    if (vpx_codec_dec_init(&v->ctx, vpx_codec_vp8_dx(), &cfg, 0)) {
        free(v); return NULL;
    }
    return v;
}
int esp_vpx_decode(struct esp_vpx *v, const uint8_t *in, size_t len, uint8_t *yuv) {
    vpx_codec_iter_t iter = NULL;
    vpx_image_t *image;
    unsigned p, y;
    if (vpx_codec_decode(&v->ctx, in, len, NULL, 0)) return -1;
    image = vpx_codec_get_frame(&v->ctx, &iter);
    if (!image || image->fmt != VPX_IMG_FMT_I420 ||
        image->d_w != v->width || image->d_h != v->height) return -2;
    for (p = 0; p < 3; p++) {
        unsigned w = p ? v->width / 2 : v->width;
        unsigned h = p ? v->height / 2 : v->height;
        for (y = 0; y < h; y++) {
            memcpy(yuv, image->planes[p] + y * image->stride[p], w);
            yuv += w;
        }
    }
    if (vpx_codec_get_frame(&v->ctx, &iter)) return -3;
    return 0;
}
