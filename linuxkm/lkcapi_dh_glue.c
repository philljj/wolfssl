/* lkcapi_dh_glue.c -- glue logic to register dh and ffdhe wolfCrypt
 * implementations with the Linux Kernel Cryptosystem
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#if defined(LINUXKM_LKCAPI_REGISTER_DH)

#ifndef LINUXKM_LKCAPI_REGISTER
    #error lkcapi_dh_glue.c included in non-LINUXKM_LKCAPI_REGISTER project.
#endif

#if defined(HAVE_FFDHE_2048) || \
    defined(HAVE_FFDHE_3072) || \
    defined(HAVE_FFDHE_6144) || \
    defined(HAVE_FFDHE_8192)
    #define LINUXKM_FFDHE
#endif

#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/dh.h>
#include <crypto/dh.h>

/* need misc.c for ForceZero(). */
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#define WOLFKM_DH_NAME    ("dh")
#define WOLFKM_DH_DRIVER  ("dh" WOLFKM_DRIVER_FIPS \
                           "-wolfcrypt")

#ifdef HAVE_FFDHE_2048
    #define WOLFKM_FFDHE2048_NAME   ("ffdhe2048(dh)")
    #define WOLFKM_FFDHE2048_DRIVER ("ffdhe2048(" WOLFKM_DRIVER_FIPS \
                                     "-wolfcrypt)")
#endif /* HAVE_FFDHE_2048 */

#ifdef HAVE_FFDHE_3072
    #define WOLFKM_FFDHE3072_NAME   ("ffdhe3072(dh)")
    #define WOLFKM_FFDHE3072_DRIVER ("ffdhe3072(" WOLFKM_DRIVER_FIPS \
                                     "-wolfcrypt)")
#endif /* HAVE_FFDHE_3072 */

#ifdef HAVE_FFDHE_4096
    #define WOLFKM_FFDHE4096_NAME   ("ffdhe4096(dh)")
    #define WOLFKM_FFDHE4096_DRIVER ("ffdhe4096(" WOLFKM_DRIVER_FIPS \
                                     "-wolfcrypt)")
#endif /* HAVE_FFDHE_4096 */

#ifdef HAVE_FFDHE_6144
    #define WOLFKM_FFDHE6144_NAME   ("ffdhe6144(dh)")
    #define WOLFKM_FFDHE6144_DRIVER ("ffdhe6144(" WOLFKM_DRIVER_FIPS \
                                     "-wolfcrypt)")
#endif /* HAVE_FFDHE_6144 */

#define DH_KPP_SECRET_MIN_SIZE (sizeof(struct kpp_secret) + 3 * sizeof(int))

static inline const u8 *km_dh_unpack_data(void *dst, const u8 *src, size_t size)
{
    memcpy(dst, src, size);
    return src + size;
}

static int km_dh_decode_key(const u8 *buf, unsigned int len, struct dh *params)
{
    const u8 *ptr = buf;
    struct kpp_secret secret;

    if (unlikely(!buf || len < DH_KPP_SECRET_MIN_SIZE))
        return -EINVAL;

    ptr = km_dh_unpack_data(&secret, ptr, sizeof(secret));
    if (secret.type != CRYPTO_KPP_SECRET_TYPE_DH)
        return -EINVAL;

    ptr = km_dh_unpack_data(&params->key_size, ptr, sizeof(params->key_size));
    ptr = km_dh_unpack_data(&params->p_size, ptr, sizeof(params->p_size));
    ptr = km_dh_unpack_data(&params->g_size, ptr, sizeof(params->g_size));
    if (secret.len != crypto_dh_key_len(params))
        return -EINVAL;

    /* Don't allocate memory. Set pointers to data within
     * the given buffer
     */
    params->key = (void *)ptr;
    params->p = (void *)(ptr + params->key_size);
    params->g = (void *)(ptr + params->key_size + params->p_size);

    return 0;
}

#ifdef WOLFKM_DEBUG_DH_VERBOSE
static void km_dump_data(const char * what, const byte * data, word32 len)
{
    char   hex_str[64];
    size_t i = 0;
    size_t j = 0;
    size_t max_len = len;

    pr_info("%s (%d):\n", what, len);

    while (len > 0) {
        memset(hex_str, '\0', sizeof(hex_str));

        for (i = 0; i < 8 && (i + j) < max_len; ++i) {
            sprintf(hex_str + (i * 6), "0x%02x, ", data[j + i]);
        }

        j   += 8;
        len -= (len < 8 ? len : 8);

        pr_info("%s\n", hex_str);
    }

    return;
}
#endif /* WOLFKM_DEBUG_DH_VERBOSE */

static inline const u8 *dh_unpack_data(void *dst, const u8 * src, size_t size)
{
    memcpy(dst, src, size);
    return src + size;
}

static int linuxkm_test_dh_driver(const char * driver,
                                  const byte * b_pub,
                                  const byte * expected_a_pub,
                                  word32 pub_len,
                                  const byte * secret,
                                  word32 secret_len,
                                  const byte * shared_secret,
                                  word32 shared_s_len);

static int dh_loaded = 0;

#ifdef HAVE_FFDHE_2048
static int ffdhe2048_loaded = 0;
#endif /* HAVE_FFDHE_2048 */

#ifdef HAVE_FFDHE_3072
static int ffdhe3072_loaded = 0;
#endif /* HAVE_FFDHE_3072 */

#ifdef HAVE_FFDHE_4096
static int ffdhe4096_loaded = 0;
#endif /* HAVE_FFDHE_4096 */

#ifdef HAVE_FFDHE_6144
static int ffdhe6144_loaded = 0;
#endif /* HAVE_FFDHE_6144 */

struct km_dh_ctx {
    WC_RNG     rng; /* needed for keypair gen and timing resistance*/
    DhKey *    key;
    byte *     priv_key;
    byte *     pub_key;
    int        name;
    word32     nbits;
    word32     priv_len;
    word32     pub_len;
    byte       needs_pub_gen;
};

/* shared misc functions */
static int          km_dh_reset_ctx(struct km_dh_ctx * ctx);
static int          km_ffdhe_init(struct crypto_kpp *tfm, int name);

/* shared callbacks */
static int          km_dh_gen_pub(struct kpp_request *req);
static int          km_dh_compute_shared_secret(struct kpp_request *req);
static unsigned int km_ffdhe_max_size(struct crypto_kpp *tfm);
static void         km_dh_exit(struct crypto_kpp *tfm);

/* alg specific callbacks */
static unsigned int km_dh_max_size(struct crypto_kpp *tfm);
static unsigned int km_ffdhe_max_size(struct crypto_kpp *tfm);
static int          km_dh_set_secret(struct crypto_kpp *tfm, const void *buf,
                                       unsigned int len);
static int          km_ffdhe_set_secret(struct crypto_kpp *tfm, const void *buf,
                                        unsigned int len);

static int          km_dh_init(struct crypto_kpp *tfm);
#ifdef HAVE_FFDHE_2048
static int          km_ffdhe2048_init(struct crypto_kpp *tfm);
#endif /* HAVE_FFDHE_2048 */
#ifdef HAVE_FFDHE_3072
static int          km_ffdhe3072_init(struct crypto_kpp *tfm);
#endif /* HAVE_FFDHE_3072 */
#ifdef HAVE_FFDHE_4096
static int          km_ffdhe4096_init(struct crypto_kpp *tfm);
#endif /* HAVE_FFDHE_4096 */
#ifdef HAVE_FFDHE_6144
static int          km_ffdhe6144_init(struct crypto_kpp *tfm);
#endif /* HAVE_FFDHE_6144 */

static struct kpp_alg dh = {
    .base.cra_name         = WOLFKM_DH_NAME,
    .base.cra_driver_name  = WOLFKM_DH_DRIVER,
    .base.cra_priority     = WOLFSSL_LINUXKM_LKCAPI_PRIORITY,
    .base.cra_module       = THIS_MODULE,
    .base.cra_ctxsize      = sizeof(struct km_dh_ctx),
    .set_secret            = km_dh_set_secret,
    .generate_public_key   = km_dh_gen_pub,
    .compute_shared_secret = km_dh_compute_shared_secret,
    .max_size              = km_dh_max_size,
    .init                  = km_dh_init,
    .exit                  = km_dh_exit,
};

#ifdef HAVE_FFDHE_2048
static struct kpp_alg ffdhe2048 = {
    .base.cra_name         = WOLFKM_FFDHE2048_NAME,
    .base.cra_driver_name  = WOLFKM_FFDHE2048_DRIVER,
    .base.cra_priority     = WOLFSSL_LINUXKM_LKCAPI_PRIORITY,
    .base.cra_module       = THIS_MODULE,
    .base.cra_ctxsize      = sizeof(struct km_dh_ctx),
    .set_secret            = km_ffdhe_set_secret,
    .generate_public_key   = km_dh_gen_pub,
    .compute_shared_secret = km_dh_compute_shared_secret,
    .max_size              = km_ffdhe_max_size,
    .init                  = km_ffdhe2048_init,
    .exit                  = km_dh_exit,
};
#endif /* HAVE_FFDHE_2048 */

#ifdef HAVE_FFDHE_3072
static struct kpp_alg ffdhe3072 = {
    .base.cra_name         = WOLFKM_FFDHE3072_NAME,
    .base.cra_driver_name  = WOLFKM_FFDHE3072_DRIVER,
    .base.cra_priority     = WOLFSSL_LINUXKM_LKCAPI_PRIORITY,
    .base.cra_module       = THIS_MODULE,
    .base.cra_ctxsize      = sizeof(struct km_dh_ctx),
    .set_secret            = km_ffdhe_set_secret,
    .generate_public_key   = km_dh_gen_pub,
    .compute_shared_secret = km_dh_compute_shared_secret,
    .max_size              = km_ffdhe_max_size,
    .init                  = km_ffdhe3072_init,
    .exit                  = km_dh_exit,
};
#endif /* HAVE_FFDHE_3072 */

#ifdef HAVE_FFDHE_4096
static struct kpp_alg ffdhe4096 = {
    .base.cra_name         = WOLFKM_FFDHE4096_NAME,
    .base.cra_driver_name  = WOLFKM_FFDHE4096_DRIVER,
    .base.cra_priority     = WOLFSSL_LINUXKM_LKCAPI_PRIORITY,
    .base.cra_module       = THIS_MODULE,
    .base.cra_ctxsize      = sizeof(struct km_dh_ctx),
    .set_secret            = km_ffdhe_set_secret,
    .generate_public_key   = km_dh_gen_pub,
    .compute_shared_secret = km_dh_compute_shared_secret,
    .max_size              = km_ffdhe_max_size,
    .init                  = km_ffdhe4096_init,
    .exit                  = km_dh_exit,
};
#endif /* HAVE_FFDHE_4096 */

#ifdef HAVE_FFDHE_6144
static struct kpp_alg ffdhe6144 = {
    .base.cra_name         = WOLFKM_FFDHE6144_NAME,
    .base.cra_driver_name  = WOLFKM_FFDHE6144_DRIVER,
    .base.cra_priority     = WOLFSSL_LINUXKM_LKCAPI_PRIORITY,
    .base.cra_module       = THIS_MODULE,
    .base.cra_ctxsize      = sizeof(struct km_dh_ctx),
    .set_secret            = km_ffdhe_set_secret,
    .generate_public_key   = km_dh_gen_pub,
    .compute_shared_secret = km_dh_compute_shared_secret,
    .max_size              = km_ffdhe_max_size,
    .init                  = km_ffdhe6144_init,
    .exit                  = km_dh_exit,
};
#endif /* HAVE_FFDHE_6144 */

/*
 *
 *
 * */
static int km_dh_reset_ctx(struct km_dh_ctx * ctx)
{
    int err = 0;
    /* clear old priv and public key arrays. */
    if (ctx->priv_key) {
        ForceZero(ctx->priv_key, ctx->priv_len);
        free(ctx->priv_key);
        ctx->priv_key = NULL;
        ctx->priv_len = 0;

        wc_FreeDhKey(ctx->key);
        err = wc_InitDhKey(ctx->key);

        if (unlikely(err)) {
            err = -ENOMEM;
            goto reset_ctx_end;
        }

        if (ctx->name) {
            err = wc_DhSetNamedKey(ctx->key, ctx->name);
            if (err) {
                #ifdef WOLFKM_DEBUG_DH
                pr_err("%s: wc_DhSetNamedKey returned: %d\n", WOLFKM_DH_DRIVER,
                       err);
                #endif /* WOLFKM_DEBUG_DH */
                err = -ENOMEM;
                goto reset_ctx_end;
            }
        }
    }

    if (ctx->pub_key) {
        free(ctx->pub_key);
        ctx->pub_key = NULL;
        ctx->pub_len = 0;
    }

    /* allocate priv and pub key arrays. */
    ctx->priv_len = DH_MAX_SIZE / WOLFSSL_BIT_SIZE;
    ctx->priv_key = malloc(ctx->priv_len);

    if (!ctx->priv_key) {
        err = -ENOMEM;
        goto reset_ctx_end;
    }

    memset(ctx->priv_key, 0, ctx->priv_len);

    ctx->pub_len = DH_MAX_SIZE / WOLFSSL_BIT_SIZE;

    ctx->pub_key = malloc(ctx->pub_len);
    if (!ctx->pub_key) {
        err = -ENOMEM;
        goto reset_ctx_end;
    }

    memset(ctx->pub_key, 0, ctx->pub_len);

reset_ctx_end:
    if (err) {
        if (ctx->priv_key) {
            ForceZero(ctx->priv_key, ctx->priv_len);
            free(ctx->priv_key);
            ctx->priv_key = NULL;
            ctx->priv_len = 0;
        }

        if (ctx->pub_key) {
            free(ctx->pub_key);
            ctx->pub_key = NULL;
            ctx->pub_len = 0;
        }
    }

    return err;
}

/**
 * Set the secret. Kernel crypto expects secret is passed with
 * struct kpp_secret as header, followed by secret data as payload.
 * See these for more info:
 *  - crypto/dh_helper.c
 *  - include/crypto/kpp.h
 *
 * dh does not accept an empty payload, unlike ffdhe, and ecdh.
 * */
static int km_dh_set_secret(struct crypto_kpp *tfm, const void *buf,
                            unsigned int len)
{
    int                err = -1;
    struct km_dh_ctx * ctx = NULL;
    struct dh          params;

    #if 0
    km_dump_data("secret", buf, len);
    #endif

    ctx = kpp_tfm_ctx(tfm);
    memset(&params, 0, sizeof(params));

    /* use decode key helper so we observe the same format. */
    if (crypto_dh_decode_key(buf, len, &params) < 0) {
        #ifdef WOLFKM_DEBUG_DH
        pr_err("%s: dh_set_secret: decode secret failed: %d",
               WOLFKM_DH_DRIVER, params.key_size);
        #endif /* WOLFKM_DEBUG_DH */
        return -EINVAL;
    }

    if (!params.key || !params.key_size || !params.p_size || !params.g_size) {
        #ifdef WOLFKM_DEBUG_DH
        pr_err("%s: dh_set_secret: empty params", WOLFKM_DH_DRIVER);
        #endif
        err = -EINVAL;
        goto dh_set_secret_end;
    }

    err = km_dh_reset_ctx(ctx);
    if (err) {
        goto dh_set_secret_end;
    }

    /* set dh params */
    err = wc_DhSetKey(ctx->key, params.p, params.p_size,
                      params.g, params.g_size);

    if (err) {
        #ifdef WOLFKM_DEBUG_DH
        pr_err("%s: wc_DhSetKey failed: %d",
               WOLFKM_DH_DRIVER, err);
        #endif
        return -EINVAL;
    }

    err = wc_DhImportKeyPair(ctx->key, params.key, params.key_size,
                             NULL, 0);

    if (err) {
        #ifdef WOLFKM_DEBUG_DH
        pr_err("%s: wc_DhImportKeyPair failed: %d",
               WOLFKM_DH_DRIVER, err);
        #endif
        return -EINVAL;
    }

    err = wc_DhExportKeyPair(ctx->key, ctx->priv_key, &ctx->priv_len,
                             NULL, NULL);

    if (err) {
        #ifdef WOLFKM_DEBUG_DH
        pr_err("%s: wc_DhExportKeyPair failed: %d\n",
               WOLFKM_DH_DRIVER, err);
        #endif
        return -EINVAL;
    }

    #if 0
    km_dump_data("p", params.p, params.p_size);
    km_dump_data("g", params.g, params.g_size);
    km_dump_data("priv", params.key, params.key_size);
    #endif

    if (unlikely(err)) {
        #ifdef WOLFKM_DEBUG_DH
        pr_err("%s: wc_DhSetKey failed: %d\n",
               WOLFKM_DH_DRIVER, err);
        #endif
        return -EINVAL;
    }

    ctx->needs_pub_gen = 1;
dh_set_secret_end:

    #ifdef WOLFKM_DEBUG_DH
    pr_info("info: exiting km_dh_set_secret\n");
    #endif /* WOLFKM_DEBUG_DH */
    return err;
}

#ifdef LINUXKM_FFDHE
/**
 * Set the secret. Kernel crypto expects secret is passed with
 * struct kpp_secret as header, followed by secret data as payload.
 * See these for more info:
 *  - crypto/dh_helper.c
 *  - include/crypto/kpp.h
 *
 * - ffdhe should not pass p or g.
 * - passing key is optional.
 * - an empty payload is optional.
 * */
static int km_ffdhe_set_secret(struct crypto_kpp *tfm, const void *buf,
                               unsigned int len)
{
    int                err = -1;
    struct km_dh_ctx * ctx = NULL;
    struct dh          params;

    ctx = kpp_tfm_ctx(tfm);
    memset(&params, 0, sizeof(params));

    #if 0
    km_dump_data("secret", buf, len);
    #endif

    if (buf) {
        /* use decode key helper so we observe the same format. */
        err = km_dh_decode_key((u8*)buf, len, &params);

        if (err) {
            #ifdef WOLFKM_DEBUG_DH
            pr_err("%s: ffdhe_set_secret: decode secret failed: %d",
                   WOLFKM_DH_DRIVER, params.key_size);
            #endif /* WOLFKM_DEBUG_DH */
            return -EINVAL;
        }

        if (params.p_size || params.g_size) {
            #ifdef WOLFKM_DEBUG_DH
            pr_err("%s: ffdhe_set_secret: unexpected p, g params: %d, %d",
                   WOLFKM_DH_DRIVER, params.p_size, params.g_size);
            #endif /* WOLFKM_DEBUG_DH */
            return -EINVAL;
        }
    }

    err = km_dh_reset_ctx(ctx);
    if (err) {
        goto dh_set_secret_end;
    }

    if (!params.key_size) {
        /* generate the ffdhe key pair*/
        #ifdef WOLFKM_DEBUG_DH
        pr_info("ffdhe gen key pair");
        #endif
        err = wc_DhGenerateKeyPair(ctx->key, &ctx->rng,
                                   ctx->priv_key, &ctx->priv_len,
                                   ctx->pub_key, &ctx->pub_len);

        if (err) {
            #ifdef WOLFKM_DEBUG_DH
            pr_err("%s: wc_DhGenerateKeyPair failed: %d",
                   WOLFKM_DH_DRIVER, err);
            #endif
            return -EINVAL;
        }

        ctx->needs_pub_gen = 0;
    }
    else {
        /* import the private key. */
        err = wc_DhImportKeyPair(ctx->key, params.key, params.key_size,
                                 NULL, 0);

        if (err) {
            #ifdef WOLFKM_DEBUG_DH
            pr_err("%s: wc_DhImportKeyPair failed: %d",
                   WOLFKM_DH_DRIVER, err);
            #endif
            return -EINVAL;
        }

        err = wc_DhExportKeyPair(ctx->key, ctx->priv_key, &ctx->priv_len,
                                 NULL, NULL);

        if (err) {
            #ifdef WOLFKM_DEBUG_DH
            pr_err("%s: wc_DhExportKeyPair failed: %d\n",
                   WOLFKM_DH_DRIVER, err);
            #endif
            return -EINVAL;
        }

        ctx->needs_pub_gen = 1;
    }

    #if 0
    km_dump_data("p", params.p, params.p_size);
    km_dump_data("g", params.g, params.g_size);
    km_dump_data("priv", params.key, params.key_size);
    #endif

    if (unlikely(err)) {
        #ifdef WOLFKM_DEBUG_DH
        pr_err("%s: wc_DhSetKey failed: %d\n",
               WOLFKM_DH_DRIVER, err);
        #endif
        return -EINVAL;
    }

dh_set_secret_end:

    #ifdef WOLFKM_DEBUG_DH
    pr_info("info: exiting km_dh_set_secret\n");
    #endif /* WOLFKM_DEBUG_DH */
    return err;
}
#endif /* LINUXKM_FFDHE */

static unsigned int km_dh_max_size(struct crypto_kpp *tfm)
{
    struct km_dh_ctx * ctx = NULL;

    ctx = kpp_tfm_ctx(tfm);

    #ifdef WOLFKM_DEBUG_DH
    pr_info("info: exiting km_dh_max_size\n");
    #endif /* WOLFKM_DEBUG_DH */
    return (ctx->nbits / WOLFSSL_BIT_SIZE);
}

static unsigned int km_ffdhe_max_size(struct crypto_kpp *tfm)
{
    struct km_dh_ctx * ctx = NULL;
    unsigned int       max_size = 0;

    ctx = kpp_tfm_ctx(tfm);

    #ifdef WOLFKM_DEBUG_DH
    pr_info("info: exiting km_dh_max_size\n");
    #endif /* WOLFKM_DEBUG_DH */
    if (ctx->key) {
        max_size = mp_unsigned_bin_size(&ctx->key->p);
    }

    return max_size;
}

static void km_dh_exit(struct crypto_kpp *tfm)
{
    struct km_dh_ctx * ctx = NULL;

    ctx = kpp_tfm_ctx(tfm);

    if (ctx->key) {
        wc_FreeDhKey(ctx->key);
        free(ctx->key);
        ctx->key = NULL;
    }

    if (ctx->priv_key) {
        ForceZero(ctx->priv_key, ctx->priv_len);
        free(ctx->priv_key);
        ctx->priv_key = NULL;
        ctx->priv_len = 0;
    }

    if (ctx->pub_key) {
        free(ctx->pub_key);
        ctx->pub_key = NULL;
        ctx->pub_len = 0;
    }

    wc_FreeRng(&ctx->rng);

    #ifdef WOLFKM_DEBUG_DH
    pr_info("info: exiting km_dh_exit\n");
    #endif /* WOLFKM_DEBUG_DH */
    return;
}

static int km_ffdhe_init(struct crypto_kpp *tfm, int name)
{
    struct km_dh_ctx * ctx = NULL;
    int                err = 0;

    ctx = kpp_tfm_ctx(tfm);
    memset(ctx, 0, sizeof(struct km_dh_ctx));
    ctx->name = name;
    ctx->nbits = DH_MAX_SIZE;

    err = wc_InitRng(&ctx->rng);
    if (err) {
        #ifdef WOLFKM_DEBUG_DH
        pr_err("%s: init rng returned: %d\n", WOLFKM_DH_DRIVER, err);
        #endif /* WOLFKM_DEBUG_DH */
        return -ENOMEM;
    }

    ctx->key = (DhKey *)malloc(sizeof(DhKey));
    if (!ctx->key) {
        return -ENOMEM;
    }

    err = wc_InitDhKey(ctx->key);
    if (err < 0) {
        free(ctx->key);
        ctx->key = NULL;
        return -ENOMEM;
    }

    if (ctx->name) {
        err = wc_DhSetNamedKey(ctx->key, ctx->name);
        if (err) {
            #ifdef WOLFKM_DEBUG_DH
            pr_err("%s: wc_DhSetNamedKey returned: %d\n", WOLFKM_DH_DRIVER,
                   err);
            #endif /* WOLFKM_DEBUG_DH */
            free(ctx->key);
            ctx->key = NULL;
            return -ENOMEM;
        }
    }

    #ifdef WOLFKM_DEBUG_DH
    pr_info("info: exiting km_dh_init: name %d,  nbits %d",
            ctx->name, ctx->nbits);
    #endif /* WOLFKM_DEBUG_DH */
    return 0;
}

static int km_dh_init(struct crypto_kpp *tfm)
{
    return km_ffdhe_init(tfm, 0);
}

#ifdef HAVE_FFDHE_2048
static int km_ffdhe2048_init(struct crypto_kpp *tfm)
{
    return km_ffdhe_init(tfm, WC_FFDHE_2048);
}
#endif /* HAVE_FFDHE_2048 */

#ifdef HAVE_FFDHE_3072
static int km_ffdhe3072_init(struct crypto_kpp *tfm)
{
    return km_ffdhe_init(tfm, WC_FFDHE_3072);
}
#endif /* HAVE_FFDHE_3072 */

#ifdef HAVE_FFDHE_4096
static int km_ffdhe4096_init(struct crypto_kpp *tfm)
{
    return km_ffdhe_init(tfm, WC_FFDHE_4096);
}
#endif /* HAVE_FFDHE_4096 */

#ifdef HAVE_FFDHE_6144
static int km_ffdhe6144_init(struct crypto_kpp *tfm)
{
    return km_ffdhe_init(tfm, WC_FFDHE_6144);
}
#endif /* HAVE_FFDHE_6144 */

/**
 * Generate the dh public key:
 *   - req->src should be null
 *   - req->dst is where we place the public key.
 * The kernel api expects raw pub key.
 * */
static int km_dh_gen_pub(struct kpp_request *req)
{
    struct crypto_kpp * tfm = NULL;
    struct km_dh_ctx *  ctx = NULL;
    int                 err = -1;

    if (req->src != NULL || req->dst == NULL) {
        return -EINVAL;
    }

    tfm = crypto_kpp_reqtfm(req);
    ctx = kpp_tfm_ctx(tfm);

    if (!ctx->priv_key || !ctx->pub_key) {
        /* key not set or invalid key state. */
        return -EINVAL;
    }

    if (ctx->needs_pub_gen == 1) {
        memset(ctx->pub_key, 0, ctx->pub_len);

        err = wc_DhGeneratePublic(ctx->key, ctx->priv_key, ctx->priv_len,
                                  ctx->pub_key, &ctx->pub_len);

        if (unlikely(err)) {
            #ifdef WOLFKM_DEBUG_DH
            pr_err("%s: wc_dh_make_key_ex failed: %d\n",
                   WOLFKM_DH_DRIVER, err);
            #endif
            return -EINVAL;
        }

        ctx->needs_pub_gen = 0;
    }

    #if 0
    km_dump_data("priv", ctx->priv_key, ctx->priv_len);
    km_dump_data("pub", ctx->pub_key, ctx->pub_len);
    #endif

    if (ctx->pub_len > req->dst_len) {
        #ifdef WOLFKM_DEBUG_DH
        pr_err("error: dst_len too small: %d", req->dst_len);
        #endif /* WOLFKM_DEBUG_DH */
        err = -EOVERFLOW;
        goto dh_gen_pub_end;
    }

    /* copy generated pub to req->dst */
    scatterwalk_map_and_copy(ctx->pub_key, req->dst, 0, ctx->pub_len, 1);

    err = 0;
dh_gen_pub_end:

    #ifdef WOLFKM_DEBUG_DH
    pr_info("info: exiting km_dh_gen_pub: %d", ctx->pub_len);
    #endif /* WOLFKM_DEBUG_DH */

    return err;
}

/**
 * Generate dh shared secret.
 *   - req->src has raw pub key from other party.
 *   - req->dst is shared secret output buffer.
 * */
static int km_dh_compute_shared_secret(struct kpp_request *req)
{
    struct crypto_kpp * tfm = NULL;
    struct km_dh_ctx *  ctx = NULL;
    int                 err = -1;
    byte *              pub = NULL;
    word32              pub_len = 0;
    byte *              shared_secret = NULL;
    word32              shared_secret_len = 0;

    if (req->src == NULL || req->dst == NULL) {
        return -EINVAL;
    }

    tfm = crypto_kpp_reqtfm(req);
    ctx = kpp_tfm_ctx(tfm);

    pub_len = ctx->nbits / WOLFSSL_BIT_SIZE;

    if (req->src_len > pub_len) {
        #ifdef WOLFKM_DEBUG_DH
        pr_err("error: got src_len %d, expected %d", req->src_len, pub_len);
        #endif /* WOLFKM_DEBUG_DH */
        err = -EINVAL;
        goto dh_shared_secret_end;
    }

    pub_len = req->src_len;

    pub = malloc(pub_len);
    if (!pub) {
        err = -ENOMEM;
        goto dh_shared_secret_end;
    }

    memset(pub, 0, pub_len);

    /* copy req->src to pub */
    scatterwalk_map_and_copy(pub, req->src, 0, req->src_len, 0);

    shared_secret_len = pub_len;
    shared_secret = malloc(shared_secret_len);
    if (!shared_secret) {
        err = -ENOMEM;
        goto dh_shared_secret_end;
    }

    err = wc_DhAgree(ctx->key, shared_secret, &shared_secret_len,
                     ctx->priv_key, ctx->priv_len, pub, pub_len);

    if (unlikely(err)) {
        #ifdef WOLFKM_DEBUG_DH
        pr_err("error: wc_dh_shared_secret returned: %d, %d\n", err,
               shared_secret_len);
        #endif
        err = -EINVAL;
        goto dh_shared_secret_end;
    }

    #if 0
    km_dump_data("pub", pub, pub_len);
    #endif

    #ifdef WOLFKM_DEBUG_DH_VERBOSE
    km_dump_data("shared_secret", shared_secret, shared_secret_len);
    #endif /* WOLFKM_DEBUG_DH_VERBOSE */

    if (req->dst_len < shared_secret_len) {
        err = -EOVERFLOW;
        goto dh_shared_secret_end;
    }

    /* copy shared_secret to req->dst */
    scatterwalk_map_and_copy(shared_secret, req->dst, 0, shared_secret_len, 1);

dh_shared_secret_end:
    if (shared_secret) { free(shared_secret); shared_secret = NULL; }
    if (pub) { free(pub); pub = NULL; }

    #ifdef WOLFKM_DEBUG_DH
    pr_info("info: exiting km_dh_compute_shared_secret: %d\n", err);
    #endif /* WOLFKM_DEBUG_DH */
    return err;
}

static int linuxkm_test_dh(void)
{
    int rc = 0;
    /* reference values from kernel crypto/testmgr.h */
    /* 529 byte secret size */
    const byte secret[] = {
#ifdef __LITTLE_ENDIAN
        0x01, 0x00, /* type */
        0x11, 0x02, /* len */
        0x00, 0x01, 0x00, 0x00, /* key_size */
        0x00, 0x01, 0x00, 0x00, /* p_size */
        0x01, 0x00, 0x00, 0x00, /* g_size */
#else
        0x00, 0x01, /* type */
        0x02, 0x11, /* len */
        0x00, 0x00, 0x01, 0x00, /* key_size */
        0x00, 0x00, 0x01, 0x00, /* p_size */
        0x00, 0x00, 0x00, 0x01, /* g_size */
#endif
        /* xa */
        0x44, 0xc1, 0x48, 0x36, 0xa7, 0x2b, 0x6f, 0x4e, 0x43, 0x03, 0x68, 0xad, 0x31, 0x00, 0xda, 0xf3,
        0x2a, 0x01, 0xa8, 0x32, 0x63, 0x5f, 0x89, 0x32, 0x1f, 0xdf, 0x4c, 0xa1, 0x6a, 0xbc, 0x10, 0x15,
        0x90, 0x35, 0xc9, 0x26, 0x41, 0xdf, 0x7b, 0xaa, 0x56, 0x56, 0x3d, 0x85, 0x44, 0xb5, 0xc0, 0x8e,
        0x37, 0x83, 0x06, 0x50, 0xb3, 0x5f, 0x0e, 0x28, 0x2c, 0xd5, 0x46, 0x15, 0xe3, 0xda, 0x7d, 0x74,
        0x87, 0x13, 0x91, 0x4f, 0xd4, 0x2d, 0xf6, 0xc7, 0x5e, 0x14, 0x2c, 0x11, 0xc2, 0x26, 0xb4, 0x3a,
        0xe3, 0xb2, 0x36, 0x20, 0x11, 0x3b, 0x22, 0xf2, 0x06, 0x65, 0x66, 0xe2, 0x57, 0x58, 0xf8, 0x22,
        0x1a, 0x94, 0xbd, 0x2b, 0x0e, 0x8c, 0x55, 0xad, 0x61, 0x23, 0x45, 0x2b, 0x19, 0x1e, 0x63, 0x3a,
        0x13, 0x61, 0xe3, 0xa0, 0x79, 0x70, 0x3e, 0x6d, 0x98, 0x32, 0xbc, 0x7f, 0x82, 0xc3, 0x11, 0xd8,
        0xeb, 0x53, 0xb5, 0xfc, 0xb5, 0xd5, 0x3c, 0x4a, 0xea, 0x92, 0x3e, 0x01, 0xce, 0x15, 0x65, 0xd4,
        0xaa, 0x85, 0xc1, 0x11, 0x90, 0x83, 0x31, 0x6e, 0xfe, 0xe7, 0x7f, 0x7d, 0xed, 0xab, 0xf9, 0x29,
        0xf8, 0xc7, 0xf1, 0x68, 0xc6, 0xb7, 0xe4, 0x1f, 0x2f, 0x28, 0xa0, 0xc9, 0x1a, 0x50, 0x64, 0x29,
        0x4b, 0x01, 0x6d, 0x1a, 0xda, 0x46, 0x63, 0x21, 0x07, 0x40, 0x8c, 0x8e, 0x4c, 0x6f, 0xb5, 0xe5,
        0x12, 0xf3, 0xc2, 0x1b, 0x48, 0x27, 0x5e, 0x27, 0x01, 0xb1, 0xaa, 0xed, 0x68, 0x9b, 0x83, 0x18,
        0x8f, 0xb1, 0xeb, 0x1f, 0x04, 0xd1, 0x3c, 0x79, 0xed, 0x4b, 0xf7, 0x0a, 0x33, 0xdc, 0xe0, 0xc6,
        0xd8, 0x02, 0x51, 0x59, 0x00, 0x74, 0x30, 0x07, 0x4c, 0x2d, 0xac, 0xe4, 0x13, 0xf1, 0x80, 0xf0,
        0xce, 0xfa, 0xff, 0xa9, 0xce, 0x29, 0x46, 0xdd, 0x9d, 0xad, 0xd1, 0xc3, 0xc6, 0x58, 0x1a, 0x63,
        /* p */
        0xb9, 0x36, 0x3a, 0xf1, 0x82, 0x1f, 0x60, 0xd3, 0x22, 0x47, 0xb8, 0xbc, 0x2d, 0x22, 0x6b, 0x81,
        0x7f, 0xe8, 0x20, 0x06, 0x09, 0x23, 0x73, 0x49, 0x9a, 0x59, 0x8b, 0x35, 0x25, 0xf8, 0x31, 0xbc,
        0x7d, 0xa8, 0x1c, 0x9d, 0x56, 0x0d, 0x1a, 0xf7, 0x4b, 0x4f, 0x96, 0xa4, 0x35, 0x77, 0x6a, 0x89,
        0xab, 0x42, 0x00, 0x49, 0x21, 0x71, 0xed, 0x28, 0x16, 0x1d, 0x87, 0x5a, 0x10, 0xa7, 0x9c, 0x64,
        0x94, 0xd4, 0x87, 0x3d, 0x28, 0xef, 0x44, 0xfe, 0x4b, 0xe2, 0xb4, 0x15, 0x8c, 0x82, 0xa6, 0xf3,
        0x50, 0x5f, 0xa8, 0xe8, 0xa2, 0x60, 0xe7, 0x00, 0x86, 0x78, 0x05, 0xd4, 0x78, 0x19, 0xa1, 0x98,
        0x62, 0x4e, 0x4a, 0x00, 0x78, 0x56, 0x96, 0xe6, 0xcf, 0xd7, 0x10, 0x1b, 0x74, 0x5d, 0xd0, 0x26,
        0x61, 0xdb, 0x6b, 0x32, 0x09, 0x51, 0xd8, 0xa5, 0xfd, 0x54, 0x16, 0x71, 0x01, 0xb3, 0x39, 0xe6,
        0x4e, 0x69, 0xb1, 0xd7, 0x06, 0x8f, 0xd6, 0x1e, 0xdc, 0x72, 0x25, 0x26, 0x74, 0xc8, 0x41, 0x06,
        0x5c, 0xd1, 0x26, 0x5c, 0xb0, 0x2f, 0xf9, 0x59, 0x13, 0xc1, 0x2a, 0x0f, 0x78, 0xea, 0x7b, 0xf7,
        0xbd, 0x59, 0xa0, 0x90, 0x1d, 0xfc, 0x33, 0x5b, 0x4c, 0xbf, 0x05, 0x9c, 0x3a, 0x3f, 0x69, 0xa2,
        0x45, 0x61, 0x4e, 0x10, 0x6a, 0xb3, 0x17, 0xc5, 0x68, 0x30, 0xfb, 0x07, 0x5f, 0x34, 0xc6, 0xfb,
        0x73, 0x07, 0x3c, 0x70, 0xf6, 0xae, 0xe7, 0x72, 0x84, 0xc3, 0x18, 0x81, 0x8f, 0xe8, 0x11, 0x1f,
        0x3d, 0x83, 0x83, 0x01, 0x2a, 0x14, 0x73, 0xbf, 0x32, 0x32, 0x2e, 0xc9, 0x4d, 0xdb, 0x2a, 0xca,
        0xee, 0x71, 0xf9, 0xda, 0xad, 0xe8, 0x82, 0x0b, 0x4d, 0x0c, 0x1f, 0xb6, 0x1d, 0xef, 0x00, 0x67,
        0x74, 0x3d, 0x95, 0xe0, 0xb7, 0xc4, 0x30, 0x8a, 0x24, 0x87, 0x12, 0x47, 0x27, 0x70, 0x0d, 0x73,
        /* g */
        0x02
    };

    /* 256 byte pub key */
    const byte b_pub[] = {
        0x2a, 0x67, 0x5c, 0xfd, 0x63, 0x5d, 0xc0, 0x97, 0x0a, 0x8b, 0xa2, 0x1f, 0xf8, 0x8a, 0xcb, 0x54,
        0xca, 0x2f, 0xd3, 0x49, 0x3f, 0x01, 0x8e, 0x87, 0xfe, 0xcc, 0x94, 0xa0, 0x3e, 0xd4, 0x26, 0x79,
        0x9a, 0x94, 0x3c, 0x11, 0x81, 0x58, 0x5c, 0x60, 0x3d, 0xf5, 0x98, 0x90, 0x89, 0x64, 0x62, 0x1f,
        0xbd, 0x05, 0x6d, 0x2b, 0xcd, 0x84, 0x40, 0x9b, 0x4a, 0x1f, 0xe0, 0x19, 0xf1, 0xca, 0x20, 0xb3,
        0x4e, 0xa0, 0x4f, 0x15, 0xcc, 0xa5, 0xfe, 0xa5, 0xb4, 0xf5, 0x0b, 0x18, 0x7a, 0x5a, 0x37, 0xaa,
        0x58, 0x00, 0x19, 0x7f, 0xe2, 0xa3, 0xd9, 0x1c, 0x44, 0x57, 0xcc, 0xde, 0x2e, 0xc1, 0x38, 0xea,
        0xeb, 0xe3, 0x90, 0x40, 0xc4, 0x6c, 0xf7, 0xcd, 0xe9, 0x22, 0x50, 0x71, 0xf5, 0x7c, 0xdb, 0x37,
        0x0e, 0x80, 0xc3, 0xed, 0x7e, 0xb1, 0x2b, 0x2f, 0xbe, 0x71, 0xa6, 0x11, 0xa5, 0x9d, 0xf5, 0x39,
        0xf1, 0xa2, 0xe5, 0x85, 0xbc, 0x25, 0x91, 0x4e, 0x84, 0x8d, 0x26, 0x9f, 0x4f, 0xe6, 0x0f, 0xa6,
        0x2b, 0x6b, 0xf9, 0x0d, 0xaf, 0x6f, 0xbb, 0xfa, 0x2d, 0x79, 0x15, 0x31, 0x57, 0xae, 0x19, 0x60,
        0x22, 0x0a, 0xf5, 0xfd, 0x98, 0x0e, 0xbf, 0x5d, 0x49, 0x75, 0x58, 0x37, 0xbc, 0x7f, 0xf5, 0x21,
        0x56, 0x1e, 0xd5, 0xb3, 0x50, 0x0b, 0xca, 0x96, 0xf3, 0xd1, 0x3f, 0xb3, 0x70, 0xa8, 0x6d, 0x63,
        0x48, 0xfb, 0x3d, 0xd7, 0x29, 0x91, 0x45, 0xb5, 0x48, 0xcd, 0xb6, 0x78, 0x30, 0xf2, 0x3f, 0x1e,
        0xd6, 0x22, 0xd6, 0x35, 0x9b, 0xf9, 0x1f, 0x85, 0xae, 0xab, 0x4b, 0xd7, 0xe0, 0xc7, 0x86, 0x67,
        0x3f, 0x05, 0x7f, 0xa6, 0x0d, 0x2f, 0x0d, 0xbf, 0x53, 0x5f, 0x4d, 0x2c, 0x6d, 0x5e, 0x57, 0x40,
        0x30, 0x3a, 0x23, 0x98, 0xf9, 0xb4, 0x32, 0xf5, 0x32, 0x83, 0xdd, 0x0b, 0xae, 0x33, 0x97, 0x2f
    };

    /* 256 byte pub key */
    const byte expected_a_pub[] = {
        0x5c, 0x24, 0xdf, 0xeb, 0x5b, 0x4b, 0xf8, 0xc5, 0xef, 0x39, 0x48, 0x82, 0xe0, 0x1e, 0x62, 0xee,
        0x8a, 0xae, 0xdf, 0x93, 0x6c, 0x2b, 0x16, 0x95, 0x92, 0x16, 0x3f, 0x16, 0x7b, 0x75, 0x03, 0x85,
        0xd9, 0xf1, 0x69, 0xc2, 0x14, 0x87, 0x45, 0xfc, 0xa4, 0x19, 0xf6, 0xf0, 0xa4, 0xf3, 0xec, 0xd4,
        0x6c, 0x5c, 0x03, 0x3b, 0x94, 0xc2, 0x2f, 0x92, 0xe4, 0xce, 0xb3, 0xe4, 0x72, 0xe8, 0x17, 0xe6,
        0x23, 0x7e, 0x00, 0x01, 0x09, 0x59, 0x13, 0xbf, 0xc1, 0x2f, 0x99, 0xa9, 0x07, 0xaa, 0x02, 0x23,
        0x4a, 0xca, 0x39, 0x4f, 0xbc, 0xec, 0x0f, 0x27, 0x4f, 0x19, 0x93, 0x6c, 0xb9, 0x30, 0x52, 0xfd,
        0x2b, 0x9d, 0x86, 0xf1, 0x06, 0x1e, 0xb6, 0x56, 0x27, 0x4a, 0xc9, 0x8a, 0xa7, 0x8a, 0x48, 0x5e,
        0xb5, 0x60, 0xcb, 0xdf, 0xff, 0x03, 0x26, 0x10, 0xbf, 0x90, 0x8f, 0x46, 0x60, 0xeb, 0x9b, 0x9a,
        0xd6, 0x6f, 0x44, 0x91, 0x03, 0x92, 0x18, 0x2c, 0x96, 0x5e, 0x40, 0x19, 0xfb, 0xf4, 0x4f, 0x3a,
        0x02, 0x7b, 0xaf, 0xcc, 0x22, 0x20, 0x79, 0xb9, 0xf8, 0x9f, 0x8f, 0x85, 0x6b, 0xec, 0x44, 0xbb,
        0xe6, 0xa8, 0x8e, 0xb1, 0xe8, 0x2c, 0xee, 0x64, 0xee, 0xf8, 0xbd, 0x00, 0xf3, 0xe2, 0x2b, 0x93,
        0xcd, 0xe7, 0xc4, 0xdf, 0xc9, 0x19, 0x46, 0xfe, 0xb6, 0x07, 0x73, 0xc1, 0x8a, 0x64, 0x79, 0x26,
        0xe7, 0x30, 0xad, 0x2a, 0xdf, 0xe6, 0x8f, 0x59, 0xf5, 0x81, 0xbf, 0x4a, 0x29, 0x91, 0xe7, 0xb7,
        0xcf, 0x48, 0x13, 0x27, 0x75, 0x79, 0x40, 0xd9, 0xd6, 0x32, 0x52, 0x4e, 0x6a, 0x86, 0xae, 0x6f,
        0xc2, 0xbf, 0xec, 0x1f, 0xc2, 0x69, 0xb2, 0xb6, 0x59, 0xe5, 0xa5, 0x17, 0xa4, 0x77, 0xb7, 0x62,
        0x46, 0xde, 0xe8, 0xd2, 0x89, 0x78, 0x9a, 0xef, 0xa3, 0xb5, 0x8f, 0x26, 0xec, 0x80, 0xda, 0x39
    };

    /* 256 byte shared secret */
    const byte shared_secret[] = {
        0x8f, 0xf3, 0xac, 0xa2, 0xea, 0x22, 0x11, 0x5c, 0x45, 0x65, 0x1a, 0x77, 0x75, 0x2e, 0xcf, 0x46,
        0x23, 0x14, 0x1e, 0x67, 0x53, 0x4d, 0x35, 0xb0, 0x38, 0x1d, 0x4e, 0xb9, 0x41, 0x9a, 0x21, 0x24,
        0x6e, 0x9f, 0x40, 0xfe, 0x90, 0x51, 0xb1, 0x06, 0xa4, 0x7b, 0x87, 0x17, 0x2f, 0xe7, 0x5e, 0x22,
        0xf0, 0x7b, 0x54, 0x84, 0x0a, 0xac, 0x0a, 0x90, 0xd2, 0xd7, 0xe8, 0x7f, 0xe7, 0xe3, 0x30, 0x75,
        0x01, 0x1f, 0x24, 0x75, 0x56, 0xbe, 0xcc, 0x8d, 0x1e, 0x68, 0x0c, 0x41, 0x72, 0xd3, 0xfa, 0xbb,
        0xe5, 0x9c, 0x60, 0xc7, 0x28, 0x77, 0x0c, 0xbe, 0x89, 0xab, 0x08, 0xd6, 0x21, 0xe7, 0x2e, 0x1a,
        0x58, 0x7a, 0xca, 0x4f, 0x22, 0xf3, 0x2b, 0x30, 0xfd, 0xf4, 0x98, 0xc1, 0xa3, 0xf8, 0xf6, 0xcc,
        0xa9, 0xe4, 0xdb, 0x5b, 0xee, 0xd5, 0x5c, 0x6f, 0x62, 0x4c, 0xd1, 0x1a, 0x02, 0x2a, 0x23, 0xe4,
        0xb5, 0x57, 0xf3, 0xf9, 0xec, 0x04, 0x83, 0x54, 0xfe, 0x08, 0x5e, 0x35, 0xac, 0xfb, 0xa8, 0x09,
        0x82, 0x32, 0x60, 0x11, 0xb2, 0x16, 0x62, 0x6b, 0xdf, 0xda, 0xde, 0x9c, 0xcb, 0x63, 0x44, 0x6c,
        0x59, 0x26, 0x6a, 0x8f, 0xb0, 0x24, 0xcb, 0xa6, 0x72, 0x48, 0x1e, 0xeb, 0xe0, 0xe1, 0x09, 0x44,
        0xdd, 0xee, 0x66, 0x6d, 0x84, 0xcf, 0xa5, 0xc1, 0xb8, 0x36, 0x74, 0xd3, 0x15, 0x96, 0xc3, 0xe4,
        0xc6, 0x5a, 0x4d, 0x23, 0x97, 0x0c, 0x5c, 0xcb, 0xa9, 0xf5, 0x29, 0xc2, 0x0e, 0xff, 0x93, 0x82,
        0xd3, 0x34, 0x49, 0xad, 0x64, 0xa6, 0xb1, 0xc0, 0x59, 0x28, 0x75, 0x60, 0xa7, 0x8a, 0xb0, 0x11,
        0x56, 0x89, 0x42, 0x74, 0x11, 0xf5, 0xf6, 0x5e, 0x6f, 0x16, 0x54, 0x6a, 0xb1, 0x76, 0x4d, 0x50,
        0x8a, 0x68, 0xc1, 0x5b, 0x82, 0xb9, 0x0d, 0x00, 0x32, 0x50, 0xed, 0x88, 0x87, 0x48, 0x92, 0x17
    };

    rc = linuxkm_test_dh_driver("dh-generic",
                                b_pub, expected_a_pub, sizeof(b_pub),
                                secret, sizeof(secret),
                                shared_secret, sizeof(shared_secret));
    if (rc) { return rc; }

    rc = linuxkm_test_dh_driver(WOLFKM_DH_DRIVER,
                                b_pub, expected_a_pub, sizeof(b_pub),
                                secret, sizeof(secret),
                                shared_secret, sizeof(shared_secret));

    return rc;
}

#ifdef HAVE_FFDHE_2048
static int linuxkm_test_ffdhe2048(void)
{
    int rc = 0;
    return rc;
}
#endif /* HAVE_FFDHE_2048 */

#ifdef HAVE_FFDHE_3072
static int linuxkm_test_ffdhe3072(void)
{
    int rc = 0;
    return rc;
}
#endif /* HAVE_FFDHE_3072 */

#ifdef HAVE_FFDHE_4096
static int linuxkm_test_ffdhe4096(void)
{
    int rc = 0;
    return rc;
}
#endif /* HAVE_FFDHE_4096 */

#ifdef HAVE_FFDHE_6144
static int linuxkm_test_ffdhe6144(void)
{
    int rc = 0;
    return rc;
}
#endif /* HAVE_FFDHE_6144 */

static int linuxkm_test_dh_driver(const char * driver,
                                  const byte * b_pub,
                                  const byte * expected_a_pub,
                                  word32 pub_len,
                                  const byte * secret,
                                  word32 secret_len,
                                  const byte * shared_secret,
                                  word32 shared_s_len)
{
    int                  test_rc = -1;
    struct crypto_kpp *  tfm = NULL;
    struct kpp_request * req = NULL;
    struct scatterlist   src, dst;
    int                  err = 0;
    byte *               src_buf = NULL;
    byte *               dst_buf = NULL;
    unsigned int         src_len = pub_len;
    unsigned int         dst_len = 0;
    /**
     * Allocate the kpp transform, and set up
     * the kpp request.
     * */
    tfm = crypto_alloc_kpp(driver, 0, 0);
    if (IS_ERR(tfm)) {
        pr_err("error: allocating kpp algorithm %s failed: %ld\n",
               driver, PTR_ERR(tfm));
        goto test_dh_end;
    }

    req = kpp_request_alloc(tfm, GFP_KERNEL);
    if (IS_ERR(req)) {
        pr_err("error: allocating kpp request %s failed\n",
               driver);
        goto test_dh_end;
    }

    err = crypto_kpp_set_secret(tfm, secret, secret_len);
    if (err) {
        pr_err("error: crypto_kpp_set_secret returned: %d\n", err);
        goto test_dh_end;
    }

    /* large enough to hold largest req output. */
    dst_len = crypto_kpp_maxsize(tfm);
    if (dst_len <= 0) {
        pr_err("error: crypto_kpp_maxsize returned: %d\n", dst_len);
        goto test_dh_end;
    }

    dst_buf = malloc(dst_len);
    if (dst_buf == NULL) {
        pr_err("error: allocating out buf failed");
        goto test_dh_end;
    }

    memset(dst_buf, 0, dst_len);

    /* generate pub key from input, and verify matches expected. */
    kpp_request_set_input(req, NULL, 0);
    sg_init_one(&dst, dst_buf, dst_len);
    kpp_request_set_output(req, &dst, dst_len);

    err = crypto_kpp_generate_public_key(req);
    if (err) {
        pr_err("error: crypto_kpp_generate_public_key returned: %d", err);
        goto test_dh_end;
    }

    if (memcmp(expected_a_pub, sg_virt(req->dst), pub_len)) {
        pr_err("error: crypto_kpp_generate_public_key: wrong output");
        goto test_dh_end;
    }

    src_buf = malloc(src_len);
    if (src_buf == NULL) {
        pr_err("error: allocating in buf failed");
        goto test_dh_end;
    }

    memcpy(src_buf, b_pub, pub_len);

    /* generate shared secret, verify matches expected value. */
    sg_init_one(&src, src_buf, src_len);
    sg_init_one(&dst, dst_buf, dst_len);
    kpp_request_set_input(req, &src, src_len);
    kpp_request_set_output(req, &dst, dst_len);

    err = crypto_kpp_compute_shared_secret(req);
    if (err) {
        pr_err("error: crypto_kpp_compute_shared_secret returned: %d", err);
        goto test_dh_end;
    }

    if (memcmp(shared_secret, sg_virt(req->dst), shared_s_len)) {
        pr_err("error: shared secret does not match");
        goto test_dh_end;
    }

    test_rc = 0;
test_dh_end:
    if (req) { kpp_request_free(req); req = NULL; }
    if (tfm) { crypto_free_kpp(tfm); tfm = NULL; }

    if (src_buf) { free(src_buf); src_buf = NULL; }
    if (dst_buf) { free(dst_buf); dst_buf = NULL; }

    #ifdef WOLFKM_DEBUG_DH
    pr_info("info: %s: self test returned: %d\n", driver, test_rc);
    #endif /* WOLFKM_DEBUG_DH */

    return test_rc;
}

#endif /* LINUXKM_LKCAPI_REGISTER_DH */
