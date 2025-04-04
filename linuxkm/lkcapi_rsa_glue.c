/* lkcapi_rsa_glue.c -- glue logic to register RSA wolfCrypt implementations
 * with the Linux Kernel Cryptosystem
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

#ifndef LINUXKM_LKCAPI_REGISTER
    #error lkcapi_rsa_glue.c included in non-LINUXKM_LKCAPI_REGISTER project.
#endif

#if !defined(NO_RSA) && \
    (defined(LINUXKM_LKCAPI_REGISTER_ALL) || \
     defined(LINUXKM_LKCAPI_REGISTER_RSA))

#if defined(WOLFSSL_RSA_VERIFY_ONLY) || \
    defined(WOLFSSL_RSA_PUBLIC_ONLY)
    #error LINUXKM_LKCAPI_REGISTER_RSA and RSA_VERIFY_ONLY not supported
#endif /* WOLFSSL_RSA_VERIFY_ONLY || WOLFSSL_RSA_PUBLIC_ONLY */

#if defined(WC_RSA_DIRECT) || defined(WC_RSA_NO_PADDING) || \
    defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
    #define LINUXKM_DIRECT_RSA
#endif /* WC_RSA_DIRECT || WC_RSA_NO_PADDING || OPENSSL_EXTRA ||
        * OPENSSL_EXTRA_X509_SMALL */

#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/rsa.h>

#define WOLFKM_RSA_NAME      "rsa"
#define WOLFKM_RSA_DRIVER    ("rsa" WOLFKM_DRIVER_SUFFIX)

#if defined(WOLFSSL_KEY_GEN)
#if defined(LINUXKM_DIRECT_RSA)
static int  linuxkm_test_rsa_driver(const char * driver, int nbits);
#endif /* LINUXKM_DIRECT_RSA */
static int  linuxkm_test_pkcs1_driver(const char * driver, int nbits,
                                      int hash_oid, word32 hash_len);
#endif /* WOLFSSL_KEY_GEN */
#ifdef WOLFKM_DEBUG_RSA_VERBOSE
static void km_rsa_dump_hex(const char * what, const byte * data,
                            word32 data_len);
#endif /* WOLFKM_DEBUG_RSA_VERBOSE */

#if defined(LINUXKM_DIRECT_RSA)
static int direct_rsa_loaded = 0;
#endif /* LINUXKM_DIRECT_RSA */
static int pkcs1_sha256_loaded = 0;
static int pkcs1_sha512_loaded = 0;

struct km_rsa_ctx {
    WC_RNG       rng;            /* needed for pkcs1 padding, and blinding */
    byte         block_enc[512]; /* large enough for RSA 4096 */
    byte         block_dec[512];
    int          hash_oid;       /* hash_oid for wc_EncodeSignature */
    unsigned int digest_len;
    int          key_len;
    RsaKey *     key;
};

/* shared rsa callbacks */
static int          km_rsa_init(struct crypto_akcipher *tfm, int hash_oid);
static void         km_rsa_exit(struct crypto_akcipher *tfm);
static int          km_rsa_set_priv(struct crypto_akcipher *tfm,
                                     const void *key, unsigned int keylen);
static int          km_rsa_set_pub(struct crypto_akcipher *tfm,
                                    const void *key, unsigned int keylen);
static unsigned int km_rsa_max_size(struct crypto_akcipher *tfm);

#if defined(LINUXKM_DIRECT_RSA)
/* direct rsa callbacks */
static int          km_direct_rsa_init(struct crypto_akcipher *tfm);
static int          km_direct_rsa_enc(struct akcipher_request *req);
static int          km_direct_rsa_dec(struct akcipher_request *req);
#endif /* LINUXKM_DIRECT_RSA */

/* pkcs1 callbacks */
static int          km_pkcs1_sha256_init(struct crypto_akcipher *tfm);
static int          km_pkcs1_sha512_init(struct crypto_akcipher *tfm);
static int          km_pkcs1_sign(struct akcipher_request *req);
static int          km_pkcs1_verify(struct akcipher_request *req);
static int          km_pkcs1_enc(struct akcipher_request *req);
static int          km_pkcs1_dec(struct akcipher_request *req);

#if defined(LINUXKM_DIRECT_RSA)
static struct akcipher_alg direct_rsa = {
    .base.cra_name        = WOLFKM_RSA_NAME,
    .base.cra_driver_name = WOLFKM_RSA_DRIVER,
    .base.cra_priority    = WOLFSSL_LINUXKM_LKCAPI_PRIORITY,
    .base.cra_module      = THIS_MODULE,
    .base.cra_ctxsize     = sizeof(struct km_rsa_ctx),
    .encrypt              = km_direct_rsa_enc,
    .decrypt              = km_direct_rsa_dec,
    .set_priv_key         = km_rsa_set_priv,
    .set_pub_key          = km_rsa_set_pub,
    .max_size             = km_rsa_max_size,
    .init                 = km_direct_rsa_init,
    .exit                 = km_rsa_exit,
};
#endif /* LINUXKM_DIRECT_RSA */

static struct akcipher_alg pkcs1_sha256 = {
    .base.cra_name        = "pkcs1pad(rsa,sha256)",
    .base.cra_driver_name = "pkcs1pad(rsa-wolfcrypt,sha256)",
    .base.cra_priority    = WOLFSSL_LINUXKM_LKCAPI_PRIORITY,
    .base.cra_module      = THIS_MODULE,
    .base.cra_ctxsize     = sizeof(struct km_rsa_ctx),
    .sign                 = km_pkcs1_sign,
    .verify               = km_pkcs1_verify,
    .encrypt              = km_pkcs1_enc,
    .decrypt              = km_pkcs1_dec,
    .set_priv_key         = km_rsa_set_priv,
    .set_pub_key          = km_rsa_set_pub,
    .max_size             = km_rsa_max_size,
    .init                 = km_pkcs1_sha256_init,
    .exit                 = km_rsa_exit,
};

static struct akcipher_alg pkcs1_sha512 = {
    .base.cra_name        = "pkcs1pad(rsa,sha512)",
    .base.cra_driver_name = "pkcs1pad(rsa-wolfcrypt,sha512)",
    .base.cra_priority    = WOLFSSL_LINUXKM_LKCAPI_PRIORITY,
    .base.cra_module      = THIS_MODULE,
    .base.cra_ctxsize     = sizeof(struct km_rsa_ctx),
    .sign                 = km_pkcs1_sign,
    .verify               = km_pkcs1_verify,
    .encrypt              = km_pkcs1_enc,
    .decrypt              = km_pkcs1_dec,
    .set_priv_key         = km_rsa_set_priv,
    .set_pub_key          = km_rsa_set_pub,
    .max_size             = km_rsa_max_size,
    .init                 = km_pkcs1_sha512_init,
    .exit                 = km_rsa_exit,
};

static int km_rsa_init(struct crypto_akcipher *tfm, int hash_oid)
{
    struct km_rsa_ctx * ctx = NULL;
    int                 ret = 0;

    ctx = akcipher_tfm_ctx(tfm);
    memset(ctx, 0, sizeof(struct km_rsa_ctx));

    ctx->key = (RsaKey *)malloc(sizeof(RsaKey));
    if (!ctx->key) {
        pr_err("%s: allocation of %zu bytes for rsa key failed.\n",
               WOLFKM_RSA_DRIVER, sizeof(RsaKey));
        return MEMORY_E;
    }

    ret = wc_InitRng(&ctx->rng);
    if (ret) {
        pr_err("%s: init rng returned: %d\n", WOLFKM_RSA_DRIVER, ret);
        return MEMORY_E;
    }

    ret = wc_InitRsaKey(ctx->key, NULL);
    if (ret) {
        pr_err("%s: init rsa key returned: %d\n", WOLFKM_RSA_DRIVER, ret);
        return MEMORY_E;
    }

    ret = wc_RsaSetRNG(ctx->key, &ctx->rng);
    if (ret) {
        pr_err("%s: rsa set rng returned: %d\n", WOLFKM_RSA_DRIVER, ret);
        return MEMORY_E;
    }

    ctx->hash_oid = hash_oid;

    switch (ctx->hash_oid) {
    case 0:
        ctx->digest_len = 0;
        break;
    case SHA256h:
        ctx->digest_len = 32;
        break;
    case SHA512h:
        ctx->digest_len = 64;
        break;
    default:
        pr_err("%s: init: unhandled hash_oid: %d\n", WOLFKM_RSA_DRIVER,
               hash_oid);
        return MEMORY_E;
    }

    #ifdef WOLFKM_DEBUG_RSA
    pr_info("info: exiting km_rsa_init: hash_oid %d\n", ctx->hash_oid);
    #endif /* WOLFKM_DEBUG_RSA */
    return 0;
}

#if defined(LINUXKM_DIRECT_RSA)
/**
 * RSA encrypt with public key.
 *
 * Requires that crypto_akcipher_set_pub_key has been called first.
 *
 * returns 0   on success
 * returns < 0 on error
 * */
static int km_direct_rsa_enc(struct akcipher_request *req)
{
    struct crypto_akcipher * tfm = NULL;
    struct km_rsa_ctx *      ctx = NULL;
    int                      err = 0;
    word32                   key_len = 0;
    word32                   out_len = 0;

    if (req->src == NULL || req->dst == NULL) {
        pr_err("error: %s: rsa encrypt: null\n",
               WOLFKM_RSA_DRIVER);
        return -EINVAL;
    }

    tfm = crypto_akcipher_reqtfm(req);
    ctx = akcipher_tfm_ctx(tfm);
    key_len = ctx->key_len;

    if (unlikely(key_len <= 0)) {
        pr_err("error: %s: rsa encrypt size returned: %d\n",
               WOLFKM_RSA_DRIVER, key_len);
        return -EINVAL;
    }

    out_len = key_len;

    if (unlikely(req->src_len > (unsigned int) key_len)) {
        pr_err("error: %s: got %d, expected %d\n",
               WOLFKM_RSA_DRIVER, req->src_len, key_len);
        return -EINVAL;
    }

    if (unlikely(req->dst_len != (unsigned int) key_len)) {
        pr_err("error: %s: got %d, expected %d\n",
               WOLFKM_RSA_DRIVER, req->dst_len, key_len);
        return -EINVAL;
    }

    /* copy req->src to ctx->block_dec */
    memset(ctx->block_dec, 0, sizeof(ctx->block_dec));
    memset(ctx->block_enc, 0, sizeof(ctx->block_enc));
    scatterwalk_map_and_copy(ctx->block_dec, req->src, 0, req->src_len, 0);

    //err = wc_RsaDirect(ctx->block_dec, key_len, ctx->block_enc,
    //                   &out_len, ctx->key, RSA_PUBLIC_ENCRYPT, &ctx->rng);

    err = wc_RsaPublicEncrypt_ex(ctx->block_dec, key_len, ctx->block_enc,
                                 out_len, ctx->key, &ctx->rng, WC_RSA_NO_PAD, 
                                 WC_HASH_TYPE_NONE, WC_MGF1NONE, NULL, 0);

    if (unlikely(err != (int) key_len || key_len != out_len)) {
        pr_err("error: %s: rsa pub enc returned: %d, %d, %d\n",
               WOLFKM_RSA_DRIVER, err, out_len, key_len);
        return -EINVAL;
    }

    /* copy ctx->block_enc to req->dst */
    scatterwalk_map_and_copy(ctx->block_enc, req->dst, 0, key_len, 1);

    #ifdef WOLFKM_DEBUG_RSA
    pr_info("info: exiting km_direct_rsa_enc\n");
    #endif /* WOLFKM_DEBUG_RSA */
    return 0;
}

/**
 * RSA decrypt with private key.
 *
 * Requires that crypto_akcipher_set_priv_key has been called first.
 *
 * returns 0   on success
 * returns < 0 on error
 * */
static int km_direct_rsa_dec(struct akcipher_request *req)
{
    struct crypto_akcipher * tfm = NULL;
    struct km_rsa_ctx *      ctx = NULL;
    int                      err = 0;
    word32                   key_len = 0;
    word32                   out_len = 0;

    if (req->src == NULL || req->dst == NULL) {
        pr_err("error: %s: rsa encrypt: null\n",
               WOLFKM_RSA_DRIVER);
        return -EINVAL;
    }

    tfm = crypto_akcipher_reqtfm(req);
    ctx = akcipher_tfm_ctx(tfm);
    key_len = ctx->key_len;

    if (unlikely(key_len <= 0)) {
        pr_err("error: %s: rsa encrypt size returned: %d\n",
               WOLFKM_RSA_DRIVER, key_len);
        return -EINVAL;
    }

    out_len = key_len;

    if (unlikely(req->src_len != (unsigned int) key_len)) {
        pr_err("error: %s: got %d, expected %d\n",
               WOLFKM_RSA_DRIVER, req->src_len, key_len);
        return -EINVAL;
    }

    if (unlikely(req->dst_len != (unsigned int) key_len)) {
        pr_err("error: %s: got %d, expected %d\n",
               WOLFKM_RSA_DRIVER, req->dst_len, key_len);
        return -EINVAL;
    }

    /* copy req->src to ctx->block_dec */
    scatterwalk_map_and_copy(ctx->block_dec, req->src, 0, req->src_len, 0);
    memset(ctx->block_enc, 0, sizeof(ctx->block_enc));

    err = wc_RsaDirect(ctx->block_dec, key_len, ctx->block_enc,
                       &out_len, ctx->key, RSA_PRIVATE_DECRYPT, &ctx->rng);

    if (unlikely(err != (int) key_len || key_len != out_len)) {
        pr_err("error: %s: rsa pub enc returned: %d, %d, %d\n",
               WOLFKM_RSA_DRIVER, err, out_len, key_len);
        return -EINVAL;
    }

    /* copy ctx->block_enc to req->dst */
    scatterwalk_map_and_copy(ctx->block_enc, req->dst, 0, key_len, 1);

    #ifdef WOLFKM_DEBUG_RSA
    pr_info("info: exiting km_direct_rsa_dec\n");
    #endif /* WOLFKM_DEBUG_RSA */
    return 0;
}
#endif /* LINUXKM_DIRECT_RSA */

/**
 * Decodes and sets the RSA private key.
 *
 * param tfm     the crypto_akcipher transform
 * param key     BER encoded private key and parameters
 * param keylen  key length
 * */
static int km_rsa_set_priv(struct crypto_akcipher *tfm, const void *key,
                            unsigned int keylen)
{
    int                 err = 0;
    struct km_rsa_ctx * ctx = NULL;
    word32              idx = 0;
    int                 key_len = 0;

    ctx = akcipher_tfm_ctx(tfm);

    if (ctx->key_len) {
        /* Free old key. */
        ctx->key_len = 0;
        wc_FreeRsaKey(ctx->key);

        err = wc_InitRsaKey(ctx->key, NULL);
        if (err) {
            pr_err("%s: init rsa key returned: %d\n", WOLFKM_RSA_DRIVER, err);
            return MEMORY_E;
        }

        err = wc_RsaSetRNG(ctx->key, &ctx->rng);
        if (err) {
            pr_err("%s: rsa set rng returned: %d\n", WOLFKM_RSA_DRIVER, err);
            return MEMORY_E;
        }
    }

    err = wc_RsaPrivateKeyDecode(key, &idx, ctx->key, keylen);

    if (unlikely(err)) {
        if (!disable_setkey_warnings) {
            pr_err("%s: wc_RsaPrivateKeyDecode failed: %d\n",
                   WOLFKM_RSA_DRIVER, err);
        }
        return -EINVAL;
    }

    key_len = wc_RsaEncryptSize(ctx->key);
    if (unlikely(key_len <= 0)) {
        pr_err("error: %s: rsa encrypt size returned: %d\n",
               WOLFKM_RSA_DRIVER, key_len);
        return -EINVAL;
    }

    ctx->key_len = (word32) key_len;

    #ifdef WOLFKM_DEBUG_RSA
    pr_info("info: exiting km_rsa_set_priv\n");
    #endif /* WOLFKM_DEBUG_RSA */
    return err;
}

/**
 * Decodes and sets the RSA pub key.
 *
 * param tfm     the crypto_akcipher transform
 * param key     BER encoded pub key and parameters
 * param keylen  key length
 * */
static int km_rsa_set_pub(struct crypto_akcipher *tfm, const void *key,
                           unsigned int keylen)
{
    int                 err = 0;
    struct km_rsa_ctx * ctx = NULL;
    word32              idx = 0;
    int                 key_len = 0;

    ctx = akcipher_tfm_ctx(tfm);

    if (ctx->key_len) {
        /* Free old key. */
        ctx->key_len = 0;
        wc_FreeRsaKey(ctx->key);

        err = wc_InitRsaKey(ctx->key, NULL);
        if (err) {
            pr_err("%s: init rsa key returned: %d\n", WOLFKM_RSA_DRIVER, err);
            return MEMORY_E;
        }

        err = wc_RsaSetRNG(ctx->key, &ctx->rng);
        if (err) {
            pr_err("%s: rsa set rng returned: %d\n", WOLFKM_RSA_DRIVER, err);
            return MEMORY_E;
        }
    }

    err = wc_RsaPublicKeyDecode(key, &idx, ctx->key, keylen);

    if (unlikely(err)) {
        if (!disable_setkey_warnings) {
            pr_err("%s: wc_RsaPublicKeyDecode failed: %d\n",
                   WOLFKM_RSA_DRIVER, err);
        }
        return -EINVAL;
    }

    key_len = wc_RsaEncryptSize(ctx->key);
    if (unlikely(key_len <= 0)) {
        pr_err("error: %s: rsa encrypt size returned: %d\n",
               WOLFKM_RSA_DRIVER, key_len);
        return -EINVAL;
    }

    ctx->key_len = (word32) key_len;

    #ifdef WOLFKM_DEBUG_RSA
    pr_info("info: exiting km_rsa_set_pub\n");
    #endif /* WOLFKM_DEBUG_RSA */
    return err;
}

/**
 * Returns dest buffer size required for key.
 * */
static unsigned int km_rsa_max_size(struct crypto_akcipher *tfm)
{
    struct km_rsa_ctx * ctx = NULL;

    ctx = akcipher_tfm_ctx(tfm);

    #ifdef WOLFKM_DEBUG_RSA
    pr_info("info: exiting km_rsa_max_size\n");
    #endif /* WOLFKM_DEBUG_RSA */
    return (unsigned int) ctx->key_len;
}

#if defined(LINUXKM_DIRECT_RSA)
static int km_direct_rsa_init(struct crypto_akcipher *tfm)
{
    return km_rsa_init(tfm, 0);
}
#endif /* LINUXKM_DIRECT_RSA */

static void km_rsa_exit(struct crypto_akcipher *tfm)
{
    struct km_rsa_ctx * ctx = NULL;

    ctx = akcipher_tfm_ctx(tfm);

    if (ctx->key) {
        wc_FreeRsaKey(ctx->key);
        free(ctx->key);
        ctx->key = NULL;
    }

    wc_FreeRng(&ctx->rng);

    #ifdef WOLFKM_DEBUG_RSA
    pr_info("info: exiting km_rsa_exit\n");
    #endif /* WOLFKM_DEBUG_RSA */
    return;
}

static int km_pkcs1_sha256_init(struct crypto_akcipher *tfm)
{
    return km_rsa_init(tfm, SHA256h);
}

static int km_pkcs1_sha512_init(struct crypto_akcipher *tfm)
{
    return km_rsa_init(tfm, SHA512h);
}

static int km_pkcs1_sign(struct akcipher_request *req)
{
    struct crypto_akcipher * tfm = NULL;
    struct km_rsa_ctx *      ctx = NULL;
    word32                   key_len = 0;
    word32                   sig_len = 0;
    word32                   enc_len = 0;

    if (req->src == NULL || req->dst == NULL) {
        pr_err("error: %s: rsa encrypt: null\n",
               WOLFKM_RSA_DRIVER);
        return -EINVAL;
    }

    tfm = crypto_akcipher_reqtfm(req);
    ctx = akcipher_tfm_ctx(tfm);
    key_len = ctx->key_len;

    if (key_len <= 0) {
        pr_err("error: %s: key_len invalid: %d\n",
               WOLFKM_RSA_DRIVER, key_len);
        return -EINVAL;
    }

    if (req->src_len + ctx->digest_len + RSA_MIN_PAD_SZ > key_len) {
        pr_err("error: %s: rsa src_len too large: %d\n",
               WOLFKM_RSA_DRIVER, req->src_len);
        return -EOVERFLOW;
    }

    if (req->dst_len < key_len) {
        pr_err("error: %s: rsa dst_len too small: %d\n",
               WOLFKM_RSA_DRIVER, req->dst_len);
        return -EOVERFLOW;
    }

    /* copy req->src to ctx->block_dec */
    scatterwalk_map_and_copy(ctx->block_dec, req->src, 0, req->src_len, 0);
    memset(ctx->block_enc, 0, sizeof(ctx->block_enc));

    /* encode message with hash oid. */
    enc_len = wc_EncodeSignature(ctx->block_enc, ctx->block_dec,
                                 req->src_len, ctx->hash_oid);
    if (unlikely(enc_len <= 0)) {
        pr_err("error: %s: wc_EncodeSignature returned: %d\n",
               WOLFKM_RSA_DRIVER, enc_len);
        return -EINVAL;
    }

    /* sign encoded message. Use block_dec for signature array. */
    sig_len = wc_RsaSSL_Sign(ctx->block_enc, enc_len, ctx->block_dec,
                             key_len, ctx->key, &ctx->rng);
    if (unlikely(sig_len <= 0)) {
        pr_err("error: %s: wc_RsaSSL_Sign returned: %d\n",
               WOLFKM_RSA_DRIVER, sig_len);
        return -EINVAL;
    }

    /* copy ctx->block_dec to req->dst */
    scatterwalk_map_and_copy(ctx->block_dec, req->dst, 0, sig_len, 1);

    #ifdef WOLFKM_DEBUG_RSA
    pr_info("info: exiting km_pkcs1_sign\n");
    #endif /* WOLFKM_DEBUG_RSA */
    return 0;
}

/**
 * Verify a pkcs1 encoded signature.
 *
 * The total size of req->src is src_len + dst_len:
 *   - src_len: signature
 *   - dst_len: digest
 *
 * dst should be null.
 * See kernel:
 *   - include/crypto/akcipher.h
 * */
static int km_pkcs1_verify(struct akcipher_request *req)
{
    struct crypto_akcipher * tfm = NULL;
    struct km_rsa_ctx *      ctx = NULL;
    word32                   sig_len = 0;
    word32                   dec_len = 0;
    word32                   msg_len = 0;
    word32                   enc_msg_len = 0;
    int                      n_diff = 0;

    if (req->src == NULL || req->dst != NULL) {
        pr_err("error: %s: pkcs1 verify: bad args\n",
               WOLFKM_RSA_DRIVER);
        return -EINVAL;
    }

    tfm = crypto_akcipher_reqtfm(req);
    ctx = akcipher_tfm_ctx(tfm);

    msg_len = req->dst_len;
    if (msg_len != ctx->digest_len) {
        pr_err("error: %s: pkcs1 verify: invalid digest: %d\n",
               WOLFKM_RSA_DRIVER, msg_len);
        return -EINVAL;
    }

    sig_len = wc_RsaEncryptSize(ctx->key);
    if (unlikely(sig_len <= 0)) {
        pr_err("error: %s: rsa encrypt size returned: %d\n",
               WOLFKM_RSA_DRIVER, sig_len);
        return -EINVAL;
    }

    if (unlikely(req->src_len != sig_len)) {
        pr_err("error: %s: pkcs1 verify: src len incorrect: %d, %d\n",
               WOLFKM_RSA_DRIVER, req->src_len, sig_len);
        return -EINVAL;
    }

    /* copy sig from req->src to ctx->block_enc */
    scatterwalk_map_and_copy(ctx->block_enc, req->src, 0, sig_len, 0);

    /* verify encoded message. */
    memset(ctx->block_dec, 0, sizeof(ctx->block_dec));
    dec_len = wc_RsaSSL_Verify(ctx->block_enc, sig_len, ctx->block_dec,
                               sig_len, ctx->key);
    if (unlikely(dec_len <= 0)) {
        pr_err("error: %s: wc_RsaSSL_Verify returned: %d\n",
               WOLFKM_RSA_DRIVER, dec_len);
        return -EINVAL;
    }

    /* Copy digest to ctx->block_enc. */
    memset(ctx->block_enc, 0, sizeof(ctx->block_enc));
    scatterwalk_map_and_copy(ctx->block_enc, req->src, sig_len, msg_len, 0);

    #ifdef WOLFKM_DEBUG_RSA_VERBOSE
    km_rsa_dump_hex("msg", ctx->block_enc, msg_len);
    #endif /* WOLFKM_DEBUG_RSA_VERBOSE */

    /* encode digest with hash oid. */
    enc_msg_len = wc_EncodeSignature(ctx->block_enc, ctx->block_enc,
                                     msg_len, ctx->hash_oid);
    if (unlikely(enc_msg_len <= 0 || enc_msg_len != dec_len)) {
        pr_err("error: %s: encode msg: %d, %d\n",
               WOLFKM_RSA_DRIVER, enc_msg_len, msg_len);
        return -EINVAL;
    }

    #ifdef WOLFKM_DEBUG_RSA_VERBOSE
    km_rsa_dump_hex("enc msg", ctx->block_enc, enc_msg_len);
    #endif /* WOLFKM_DEBUG_RSA_VERBOSE */

    n_diff = memcmp(ctx->block_enc, ctx->block_dec, dec_len);
    if (unlikely(n_diff != 0)) {
        pr_err("error: %s: did not recover encoded digest: "
               "%d, %d\n",
               WOLFKM_RSA_DRIVER, n_diff, dec_len);
        return -EKEYREJECTED;
    }

    #ifdef WOLFKM_DEBUG_RSA
    pr_info("info: exiting km_pkcs1_verify\n");
    #endif /* WOLFKM_DEBUG_RSA */
    return 0;
}

static int km_pkcs1_enc(struct akcipher_request *req)
{
    struct crypto_akcipher * tfm = NULL;
    struct km_rsa_ctx *      ctx = NULL;
    int                      err = 0;
    word32                   key_len = 0;

    if (req->src == NULL || req->dst == NULL) {
        pr_err("error: %s: rsa encrypt: null\n",
               WOLFKM_RSA_DRIVER);
        return -EINVAL;
    }

    tfm = crypto_akcipher_reqtfm(req);
    ctx = akcipher_tfm_ctx(tfm);
    key_len = ctx->key_len;

    if (key_len <= 0) {
        pr_err("error: %s: key_len invalid: %d\n",
               WOLFKM_RSA_DRIVER, key_len);
        return -EINVAL;
    }

    if (req->src_len + RSA_MIN_PAD_SZ > key_len) {
        pr_err("error: %s: rsa src_len too large: %d\n",
               WOLFKM_RSA_DRIVER, req->src_len);
        return -EOVERFLOW;
    }

    if (req->dst_len < key_len) {
        pr_err("error: %s: rsa dst_len too small: %d\n",
               WOLFKM_RSA_DRIVER, req->dst_len);
        return -EOVERFLOW;
    }

    /* copy req->src to ctx->block_dec */
    scatterwalk_map_and_copy(ctx->block_dec, req->src, 0, req->src_len, 0);
    memset(ctx->block_enc, 0, sizeof(ctx->block_enc));

    err = wc_RsaPublicEncrypt(ctx->block_dec, key_len, ctx->block_enc,
                              key_len, ctx->key, &ctx->rng);

    if (unlikely(err != (int) key_len)) {
        pr_err("error: %s: rsa pub enc returned: %d, %d\n",
               WOLFKM_RSA_DRIVER, err, key_len);
        return -EINVAL;
    }

    /* copy ctx->block_enc to req->dst */
    scatterwalk_map_and_copy(ctx->block_enc, req->dst, 0, key_len, 1);

    #ifdef WOLFKM_DEBUG_RSA
    pr_info("info: exiting km_pkcs1_enc\n");
    #endif /* WOLFKM_DEBUG_RSA */
    return 0;
}

static int km_pkcs1_dec(struct akcipher_request *req)
{
    struct crypto_akcipher * tfm = NULL;
    struct km_rsa_ctx *      ctx = NULL;
    word32                   key_len = 0;
    word32                   dec_len = 0;

    if (req->src == NULL || req->dst == NULL) {
        pr_err("error: %s: rsa encrypt: null\n",
               WOLFKM_RSA_DRIVER);
        return -EINVAL;
    }

    tfm = crypto_akcipher_reqtfm(req);
    ctx = akcipher_tfm_ctx(tfm);
    key_len = ctx->key_len;

    if (key_len <= 0) {
        pr_err("error: %s: key_len invalid: %d\n",
               WOLFKM_RSA_DRIVER, key_len);
        return -EINVAL;
    }

    if (req->src_len != key_len) {
        pr_err("error: %s: rsa src_len too large: %d\n",
               WOLFKM_RSA_DRIVER, req->src_len);
        return -EOVERFLOW;
    }

    /* copy req->src to ctx->block_enc */
    scatterwalk_map_and_copy(ctx->block_enc, req->src, 0, req->src_len, 0);
    memset(ctx->block_dec, 0, sizeof(ctx->block_enc));

    dec_len = wc_RsaPrivateDecrypt(ctx->block_enc, key_len, ctx->block_dec,
                                   req->dst_len, ctx->key);

    if (unlikely(dec_len <= 0 || dec_len > key_len ||
        dec_len > req->dst_len)) {
        pr_err("error: %s: rsa private decrypt returned: %d, %d\n",
               WOLFKM_RSA_DRIVER, dec_len, key_len);
        return -EINVAL;
    }

    /* copy ctx->block_enc to req->dst */
    scatterwalk_map_and_copy(ctx->block_enc, req->dst, 0, dec_len, 1);

    #ifdef WOLFKM_DEBUG_RSA
    pr_info("info: exiting km_pkcs1_dec\n");
    #endif /* WOLFKM_DEBUG_RSA */
    return 0;
}

#if defined(LINUXKM_DIRECT_RSA) && defined(WC_RSA_NO_PADDING)
/**
 * Tests implemented below.
 * */
static int linuxkm_test_rsa(void)
{
    int rc = 0;
    rc = rsa_no_pad_test();
    if (rc != 0) {
        pr_err("rsa_no_pad_test() failed with retval %d.\n", rc);
        return rc;
    }

    #ifdef WOLFSSL_KEY_GEN
    /* test wolfcrypt RSA API vs wolfkm RSA driver. */
    rc = linuxkm_test_rsa_driver(WOLFKM_RSA_DRIVER, 2048);
    if (rc) { return rc; }

    rc = linuxkm_test_rsa_driver(WOLFKM_RSA_DRIVER, 3072);
    if (rc) { return rc; }

    rc = linuxkm_test_rsa_driver(WOLFKM_RSA_DRIVER, 4096);
    if (rc) { return rc; }


    #ifdef WOLFKM_DEBUG_RSA
    /* repeat test against stock linux RSA akcipher. */
    rc = linuxkm_test_rsa_driver("rsa-generic", 2048);
    if (rc) { return rc; }

    rc = linuxkm_test_rsa_driver("rsa-generic", 3072);
    if (rc) { return rc; }

    rc = linuxkm_test_rsa_driver("rsa-generic", 4096);
    if (rc) { return rc; }
    #endif /* WOLFKM_DEBUG_RSA */
    #endif /* WOLFSSL_KEY_GEN */

    return rc;
}
#endif /* LINUXKM_DIRECT_RSA */

static int linuxkm_test_pkcs1_sha256(void)
{
    int rc = 0;

    #ifdef WOLFSSL_KEY_GEN
    #ifdef WOLFKM_DEBUG_RSA
    rc = linuxkm_test_pkcs1_driver("pkcs1pad(rsa-generic,sha256)", 2048,
                                   SHA256h, 32);
    if (rc) { return rc; }

    rc = linuxkm_test_pkcs1_driver("pkcs1pad(rsa-generic,sha256)", 3072,
                                   SHA256h, 32);
    if (rc) { return rc; }

    rc = linuxkm_test_pkcs1_driver("pkcs1pad(rsa-generic,sha256)", 4096,
                                   SHA256h, 32);
    if (rc) { return rc; }
    #endif /* WOLFKM_DEBUG_RSA */

    rc = linuxkm_test_pkcs1_driver("pkcs1pad(rsa-wolfcrypt,sha256)", 2048,
                                   SHA256h, 32);
    if (rc) { return rc; }

    rc = linuxkm_test_pkcs1_driver("pkcs1pad(rsa-wolfcrypt,sha256)", 3072,
                                   SHA256h, 32);
    if (rc) { return rc; }

    rc = linuxkm_test_pkcs1_driver("pkcs1pad(rsa-wolfcrypt,sha256)", 4096,
                                   SHA256h, 32);
    if (rc) { return rc; }
    #endif /* WOLFSSL_KEY_GEN */

    return rc;
}

static int linuxkm_test_pkcs1_sha512(void)
{
    int rc = 0;

    #ifdef WOLFSSL_KEY_GEN
    #ifdef WOLFKM_DEBUG_RSA
    rc = linuxkm_test_pkcs1_driver("pkcs1pad(rsa-generic,sha512)", 2048,
                                   SHA512h, 64);
    if (rc) { return rc; }

    rc = linuxkm_test_pkcs1_driver("pkcs1pad(rsa-generic,sha512)", 3072,
                                   SHA512h, 64);
    if (rc) { return rc; }

    rc = linuxkm_test_pkcs1_driver("pkcs1pad(rsa-generic,sha512)", 4096,
                                   SHA512h, 64);
    if (rc) { return rc; }
    #endif /* WOLFKM_DEBUG_RSA */

    rc = linuxkm_test_pkcs1_driver("pkcs1pad(rsa-wolfcrypt,sha512)", 2048,
                                   SHA512h, 64);
    if (rc) { return rc; }

    rc = linuxkm_test_pkcs1_driver("pkcs1pad(rsa-wolfcrypt,sha512)", 3072,
                                   SHA512h, 64);
    if (rc) { return rc; }

    rc = linuxkm_test_pkcs1_driver("pkcs1pad(rsa-wolfcrypt,sha512)", 4096,
                                   SHA512h, 64);
    if (rc) { return rc; }
    #endif /* WOLFSSL_KEY_GEN */

    return rc;
}

#if defined(LINUXKM_DIRECT_RSA) && defined(WOLFSSL_KEY_GEN)
/**
 * Test linux kernel crypto driver:
 *   1. generate RSA key with wolfcrypt.
 *   2. sanity check wolfcrypt encrypt + decrypt.
 *   3. crypto_alloc_akcipher(driver)
 *   4. export wolfcrypt RSA der pub/priv, load to akcipher tfm with
 *      crypto_akcipher_set_pub_key, crypto_akcipher_set_priv_key.
 *   5. test: kernel public encrypt + wolfcrypt private decrypt
 *   6. test: wolfcrypt public encrypt + kernel private decrypt
 * */
static int linuxkm_test_rsa_driver(const char * driver, int nbits)
{
    int                       test_rc = -1;
    int                       ret = 0;
    struct crypto_akcipher *  tfm = NULL;
    struct akcipher_request * req = NULL;
    RsaKey *                  key = NULL;
    WC_RNG                    rng;
    byte *                    priv = NULL; /* priv der */
    word32                    priv_len = 0;
    byte *                    pub = NULL; /* pub der */
    word32                    pub_len = 0;
    byte                      init_rng = 0;
    byte                      init_key = 0;
    static const byte         p_vector[] =
    /* Now is the time for all good men w/o trailing 0 */
    {
        0x4e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
        0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20,
        0x66,0x6f,0x72,0x20,0x61,0x6c,0x6c,0x20,
        0x67,0x6f,0x6f,0x64,0x20,0x6d,0x65,0x6e
    };
    byte *                    enc = NULL;
    byte *                    dec = NULL; /* wc decrypt */
    byte *                    plaintext = NULL; /* km decrypt */
    word32                    key_len = 0;
    word32                    out_len = 0;
    int                       enc_ret = 0;
    int                       dec_ret = 0;
    int                       n_diff = 0;
    struct scatterlist        src, dst;
    size_t                    i = 0;

    key = (RsaKey*)malloc(sizeof(RsaKey));
    if (key == NULL) {
        pr_err("error: allocating key(%zu) failed\n", sizeof(RsaKey));
        goto test_rsa_end;
    }

    memset(&rng, 0, sizeof(rng));
    memset(key, 0, sizeof(RsaKey));

    ret = wc_InitRng(&rng);
    if (ret) {
        pr_err("error: init rng returned: %d\n", ret);
        goto test_rsa_end;
    }
    init_rng = 1;

    ret = wc_InitRsaKey(key, NULL);
    if (ret) {
        pr_err("error: init rsa key returned: %d\n", ret);
        goto test_rsa_end;
    }
    init_key = 1;

    ret = wc_RsaSetRNG(key, &rng);
    if (ret) {
        pr_err("error: rsa set rng returned: %d\n", ret);
        goto test_rsa_end;
    }

    ret = wc_MakeRsaKey(key, nbits, WC_RSA_EXPONENT, &rng);
    if (ret) {
        pr_err("error: make rsa key returned: %d\n", ret);
        goto test_rsa_end;
    }

    key_len = wc_RsaEncryptSize(key);
    if (key_len <= 0) {
        pr_err("error: rsa encrypt size returned: %d\n", key_len);
        goto test_rsa_end;
    }

    /**
     * Allocate buffers based on the RsaKey key_len.
     *
     * Add +1 for dec and plaintext arrays to printf nicely.
     * */
    enc = (byte*)malloc(key_len);
    if (enc == NULL) {
        pr_err("error: allocating enc(%d) failed\n", key_len);
        goto test_rsa_end;
    }

    dec = (byte*)malloc(key_len + 1);
    if (dec == NULL) {
        pr_err("error: allocating dec(%d) failed\n", key_len);
        goto test_rsa_end;
    }

    plaintext = (byte*)malloc(key_len + 1);
    if (plaintext == NULL) {
        pr_err("error: allocating plaintext(%d) failed\n", key_len);
        goto test_rsa_end;
    }

    memset(enc,  0, key_len);
    memset(dec,  0, key_len + 1);
    memset(plaintext, 0, key_len + 1);

    /* Fill up dec and plaintext with plaintext reference. */
    for (i = 0; i < key_len / sizeof(p_vector); ++i) {
        memcpy(dec  + i * sizeof(p_vector), p_vector, sizeof(p_vector));
        memcpy(plaintext + i * sizeof(p_vector), p_vector, sizeof(p_vector));
    }

    /**
     * Sanity test: first encrypt and decrypt with direct wolfcrypt API.
     * */
    out_len = key_len;
    enc_ret = wc_RsaDirect(dec, key_len, enc, &out_len, key,
                           RSA_PUBLIC_ENCRYPT, &rng);
    if (enc_ret != (int) key_len || key_len != out_len) {
        pr_err("error: rsa pub enc returned: %d, %d\n", enc_ret, out_len);
        ret = -1;
        goto test_rsa_end;
    }

    #ifdef WOLFKM_DEBUG_RSA_VERBOSE
    km_rsa_dump_hex("enc", enc, key_len);
    #endif /* WOLFKM_DEBUG_RSA_VERBOSE */

    memset(dec, 0, key_len);
    dec_ret = wc_RsaDirect(enc, key_len, dec, &out_len, key,
                           RSA_PRIVATE_DECRYPT, &rng);
    if (dec_ret != (int) key_len || key_len != out_len) {
        pr_err("error: rsa priv dec returned: %d, %d\n", dec_ret, out_len);
        goto test_rsa_end;
    }

    /* dec and plaintext should match now. */
    n_diff = memcmp(dec, plaintext, key_len);
    if (n_diff) {
        pr_err("error: decrypt doesn't match plain: %d\n", n_diff);
        goto test_rsa_end;
    }

    /**
     * Now export Rsa Der to pub and priv.
     * */
    priv_len = wc_RsaKeyToDer(key, NULL, 0);
    if (priv_len <= 0) {
        pr_err("error: rsa priv to der returned: %d\n", priv_len);
        goto test_rsa_end;
    }

    priv = (byte*)malloc(priv_len);
    if (priv == NULL) {
        pr_err("error: allocating priv(%d) failed\n", priv_len);
        goto test_rsa_end;
    }

    memset(priv, 0, priv_len);

    priv_len = wc_RsaKeyToDer(key, priv, priv_len);
    if (priv_len <= 0) {
        pr_err("error: rsa priv to der returned: %d\n", priv_len);
        goto test_rsa_end;
    }

    /* get rsa pub der */
    pub_len = wc_RsaKeyToPublicDer(key, NULL, 0);
    if (pub_len <= 0) {
        pr_err("error: rsa pub to der returned: %d\n", pub_len);
        goto test_rsa_end;
    }

    pub = (byte*)malloc(pub_len);
    if (pub == NULL) {
        pr_err("error: allocating pub(%d) failed\n", pub_len);
        goto test_rsa_end;
    }

    memset(pub, 0, pub_len);

    pub_len = wc_RsaKeyToPublicDer(key, pub, pub_len);
    if (pub_len <= 0) {
        pr_err("error: rsa pub to der returned: %d\n", pub_len);
        goto test_rsa_end;
    }

    /**
     * Now allocate the akcipher transform, and set up
     * the akcipher request.
     * */
    tfm = crypto_alloc_akcipher(driver, 0, 0);
    if (IS_ERR(tfm)) {
        pr_err("error: allocating akcipher algorithm %s failed: %ld\n",
               driver, PTR_ERR(tfm));
        goto test_rsa_end;
    }

    req = akcipher_request_alloc(tfm, GFP_KERNEL);
    if (IS_ERR(req)) {
        pr_err("error: allocating akcipher request %s failed\n",
               driver);
        goto test_rsa_end;
    }

    ret = crypto_akcipher_set_pub_key(tfm, pub + 24, pub_len - 24);
    if (ret) {
        pr_err("error: crypto_akcipher_set_pub_key returned: %d\n", ret);
        goto test_rsa_end;
    }

    {
        unsigned int maxsize = crypto_akcipher_maxsize(tfm);
        if (maxsize != key_len) {
            pr_err("error: crypto_akcipher_maxsize "
                   "returned %d, expected %d\n", maxsize, key_len);
            goto test_rsa_end;
        }
    }

    /* kernel module encrypt */
    sg_init_one(&src, dec, key_len);
    sg_init_one(&dst, enc, key_len);

    akcipher_request_set_crypt(req, &src, &dst, key_len, key_len);

    ret = crypto_akcipher_encrypt(req);
    if (ret) {
        pr_err("error: crypto_akcipher_encrypt returned: %d\n", ret);
        goto test_rsa_end;
    }

    #ifdef WOLFKM_DEBUG_RSA_VERBOSE
    km_rsa_dump_hex("enc", enc, key_len);
    #endif /* WOLFKM_DEBUG_RSA_VERBOSE */
    memset(dec, 0, key_len + 1);
    dec_ret = wc_RsaDirect(enc, key_len, dec, &out_len, key,
                           RSA_PRIVATE_DECRYPT, &rng);

    if (dec_ret != (int) key_len || key_len != out_len) {
        pr_err("error: rsa priv dec returned: %d, %d\n", dec_ret, out_len);
        goto test_rsa_end;
    }

    n_diff = memcmp(dec, plaintext, key_len);
    if (n_diff) {
        pr_err("error: decrypt doesn't match plain: %d\n", n_diff);
        goto test_rsa_end;
    }

    /* kernel module decrypt with rsa private key */
    enc_ret = wc_RsaDirect(dec, key_len, enc, &out_len, key,
                           RSA_PUBLIC_ENCRYPT, &rng);

    if (enc_ret != (int) key_len || key_len != out_len) {
        pr_err("error: rsa pub enc returned: %d, %d\n", enc_ret, out_len);
        ret = -1;
        goto test_rsa_end;
    }

    ret = crypto_akcipher_set_priv_key(tfm, priv, priv_len);
    if (ret) {
        pr_err("error: crypto_akcipher_set_priv_key returned: %d\n", ret);
        goto test_rsa_end;
    }

    {
        unsigned int maxsize = crypto_akcipher_maxsize(tfm);
        if (maxsize != key_len) {
            pr_err("error: crypto_akcipher_maxsize "
                   "returned %d, expected %d\n", maxsize, key_len);
            goto test_rsa_end;
        }
    }

    sg_init_one(&src, enc, key_len);
    sg_init_one(&dst, dec, key_len);

    akcipher_request_set_crypt(req, &src, &dst, key_len, key_len);

    memset(dec, 0, key_len);
    ret = crypto_akcipher_decrypt(req);
    if (ret) {
        pr_err("error: crypto_akcipher_decrypt returned: %d\n", ret);
        goto test_rsa_end;
    }

    n_diff = memcmp(dec, plaintext, key_len);
    if (n_diff) {
        pr_err("error: decrypt doesn't match plain: %d\n", n_diff);
        goto test_rsa_end;
    }

    test_rc = 0;

test_rsa_end:
    if (req) { akcipher_request_free(req); req = NULL; }
    if (tfm) { crypto_free_akcipher(tfm); tfm = NULL; }

    if (init_rng) { wc_FreeRng(&rng); init_rng = 0; }
    if (init_key) { wc_FreeRsaKey(key); init_key = 0; }

    if (enc) { free(enc); enc = NULL; }
    if (dec) { free(dec); dec = NULL; }
    if (plaintext) { free(plaintext); plaintext = NULL; }

    if (key) { free(key); key = NULL; }
    if (priv) { free(priv); priv = NULL; }
    if (pub) { free(pub); pub = NULL; }

    #ifdef WOLFKM_DEBUG_RSA
    pr_info("info: %s, %d, %d: self test returned: %d\n", driver,
            nbits, key_len, ret);
    #endif /* WOLFKM_DEBUG_RSA */

    return test_rc;
}
#endif /* LINUXKM_DIRECT_RSA */

#if defined(WOLFSSL_KEY_GEN)
static int linuxkm_test_pkcs1_driver(const char * driver, int nbits,
                                     int hash_oid, word32 hash_len)
{
    int                       test_rc = -1;
    int                       ret = 0;
    struct crypto_akcipher *  tfm = NULL;
    struct akcipher_request * req = NULL;
    RsaKey *                  key = NULL;
    WC_RNG                    rng;
    byte *                    priv = NULL; /* priv der */
    word32                    priv_len = 0;
    byte *                    pub = NULL; /* pub der */
    word32                    pub_len = 0;
    byte                      init_rng = 0;
    byte                      init_key = 0;
    static const byte         p_vector[] =
    /* Now is the time for all good men w/o trailing 0 */
    {
        0x4e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
        0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20,
        0x66,0x6f,0x72,0x20,0x61,0x6c,0x6c,0x20,
        0x67,0x6f,0x6f,0x64,0x20,0x6d,0x65,0x6e
    };
    byte                      hash[WC_SHA512_DIGEST_SIZE];
    byte *                    sig = NULL;
    byte *                    km_sig = NULL;
    byte *                    dec = NULL;
    byte *                    enc = NULL;
    word32                    key_len = 0;
    word32                    sig_len = 0;
    word32                    enc_len = 0;
    struct scatterlist        src, dst;
    struct scatterlist        src_tab[2];
    int                       n_diff = 0;

    /* hash the test msg with hash algo. */
    ret = wc_Hash(wc_OidGetHash(hash_oid), p_vector, sizeof(p_vector),
                  hash, hash_len);
    if (ret) {
        pr_err("error: wc_Hash returned: %d\n", ret);
        goto test_pkcs1_end;
    }

    key = (RsaKey*)malloc(sizeof(RsaKey));
    if (key == NULL) {
        pr_err("error: allocating key(%zu) failed\n", sizeof(RsaKey));
        goto test_pkcs1_end;
    }

    memset(&rng, 0, sizeof(rng));
    memset(key, 0, sizeof(RsaKey));

    ret = wc_InitRng(&rng);
    if (ret) {
        pr_err("error: init rng returned: %d\n", ret);
        goto test_pkcs1_end;
    }
    init_rng = 1;

    ret = wc_InitRsaKey(key, NULL);
    if (ret) {
        pr_err("error: init rsa key returned: %d\n", ret);
        goto test_pkcs1_end;
    }
    init_key = 1;

    ret = wc_RsaSetRNG(key, &rng);
    if (ret) {
        pr_err("error: rsa set rng returned: %d\n", ret);
        goto test_pkcs1_end;
    }

    ret = wc_MakeRsaKey(key, nbits, WC_RSA_EXPONENT, &rng);
    if (ret) {
        pr_err("error: make rsa key returned: %d\n", ret);
        goto test_pkcs1_end;
    }

    key_len = wc_RsaEncryptSize(key);
    if (key_len <= 0) {
        pr_err("error: rsa encrypt size returned: %d\n", key_len);
        goto test_pkcs1_end;
    }

    sig = (byte*)malloc(key_len);
    if (sig == NULL) {
        pr_err("error: allocating sig(%d) failed\n", key_len);
        goto test_pkcs1_end;
    }
    memset(sig, 0, key_len);

    km_sig = (byte*)malloc(key_len);
    if (km_sig == NULL) {
        pr_err("error: allocating km_sig(%d) failed\n", key_len);
        goto test_pkcs1_end;
    }
    memset(km_sig, 0, key_len);

    enc = (byte*)malloc(key_len);
    if (enc == NULL) {
        pr_err("error: allocating enc(%d) failed\n", key_len);
        goto test_pkcs1_end;
    }
    memset(enc, 0, key_len);

    dec = (byte*)malloc(key_len + 1);
    if (dec == NULL) {
        pr_err("error: allocating dec(%d) failed\n", key_len);
        goto test_pkcs1_end;
    }
    memset(dec, 0, key_len + 1);

    /**
     * Now export Rsa Der to pub and priv.
     * */
    priv_len = wc_RsaKeyToDer(key, NULL, 0);
    if (priv_len <= 0) {
        pr_err("error: rsa priv to der returned: %d\n", priv_len);
        goto test_pkcs1_end;
    }

    priv = (byte*)malloc(priv_len);
    if (priv == NULL) {
        pr_err("error: allocating priv(%d) failed\n", priv_len);
        goto test_pkcs1_end;
    }

    memset(priv, 0, priv_len);

    priv_len = wc_RsaKeyToDer(key, priv, priv_len);
    if (priv_len <= 0) {
        pr_err("error: rsa priv to der returned: %d\n", priv_len);
        goto test_pkcs1_end;
    }

    /* get rsa pub der */
    pub_len = wc_RsaKeyToPublicDer(key, NULL, 0);
    if (pub_len <= 0) {
        pr_err("error: rsa pub to der returned: %d\n", pub_len);
        goto test_pkcs1_end;
    }

    pub = (byte*)malloc(pub_len);
    if (pub == NULL) {
        pr_err("error: allocating pub(%d) failed\n", pub_len);
        goto test_pkcs1_end;
    }

    memset(pub, 0, pub_len);

    pub_len = wc_RsaKeyToPublicDer(key, pub, pub_len);
    if (pub_len <= 0) {
        pr_err("error: rsa pub to der returned: %d\n", pub_len);
        goto test_pkcs1_end;
    }

    /**
     * Sanity test: first sign and verify with direct wolfcrypt API.
     * */

    /* encode the hash. */
    enc_len = wc_EncodeSignature(enc, hash, hash_len, hash_oid);
    if (enc_len <= 0) {
        pr_err("error: wc_EncodeSignature returned: %d\n", enc_len);
        goto test_pkcs1_end;
    }

    sig_len = wc_RsaSSL_Sign(enc, enc_len, sig, key_len, key, &rng);
    if (sig_len <= 0) {
        pr_err("error: wc_RsaSSL_Sign returned: %d\n", sig_len);
        goto test_pkcs1_end;
    }

    #ifdef WOLFKM_DEBUG_RSA_VERBOSE
    km_rsa_dump_hex("sig", sig, sig_len);
    #endif /* WOLFKM_DEBUG_RSA_VERBOSE */

    memset(dec, 0, key_len + 1);
    ret = wc_RsaSSL_Verify(sig, key_len, dec, enc_len, key);
    if (ret <= 0 || ret != (int) enc_len) {
        pr_err("error: wc_RsaSSL_Verify returned %d, expected %d\n" , ret,
               enc_len);
        goto test_pkcs1_end;
    }

    /* dec and enc should match now. */
    n_diff = memcmp(dec, enc, enc_len);
    if (n_diff) {
        pr_err("error: decrypt doesn't match plain: %d\n", n_diff);
        goto test_pkcs1_end;
    }

    /**
     * Allocate the akcipher transform, and set up
     * the akcipher request.
     * */
    tfm = crypto_alloc_akcipher(driver, 0, 0);
    if (IS_ERR(tfm)) {
        pr_err("error: allocating akcipher algorithm %s failed: %ld\n",
               driver, PTR_ERR(tfm));
        goto test_pkcs1_end;
    }

    req = akcipher_request_alloc(tfm, GFP_KERNEL);
    if (IS_ERR(req)) {
        pr_err("error: allocating akcipher request %s failed\n",
               driver);
        goto test_pkcs1_end;
    }

    ret = crypto_akcipher_set_priv_key(tfm, priv, priv_len);
    if (ret) {
        pr_err("error: crypto_akcipher_set_priv_key returned: %d\n", ret);
        goto test_pkcs1_end;
    }

    {
        unsigned int maxsize = crypto_akcipher_maxsize(tfm);
        if (maxsize != key_len) {
            pr_err("error: crypto_akcipher_maxsize "
                   "returned %d, expected %d\n", maxsize, key_len);
            goto test_pkcs1_end;
        }
    }

    sg_init_one(&src, hash, hash_len);
    sg_init_one(&dst, km_sig, key_len);
    memset(km_sig, 0, key_len);

    akcipher_request_set_crypt(req, &src, &dst, hash_len, key_len);

    ret = crypto_akcipher_sign(req);
    if (ret) {
        pr_err("error: crypto_akcipher_sign returned: %d\n", ret);
        goto test_pkcs1_end;
    }

    #ifdef WOLFKM_DEBUG_RSA_VERBOSE
    km_rsa_dump_hex("km_sig", km_sig, key_len);
    #endif /* WOLFKM_DEBUG_RSA_VERBOSE */

    /* now set pub key for verify test. */
    ret = crypto_akcipher_set_pub_key(tfm, pub + 24, pub_len - 24);
    if (ret) {
        pr_err("error: crypto_akcipher_set_pub_key returned: %d\n", ret);
        goto test_pkcs1_end;
    }

    {
        unsigned int maxsize = crypto_akcipher_maxsize(tfm);
        if (maxsize != key_len) {
            pr_err("error: crypto_akcipher_maxsize "
                   "returned %d, expected %d\n", maxsize, key_len);
            goto test_pkcs1_end;
        }
    }

    /**
     * Set sig as src, and null as dst.
     * src_tab is:
     *   src_tab[0]: signature
     *   src_tab[1]: message (digest)
     *
     * src_len is sig size plus digest size. */
    sg_init_table(src_tab, 2);
    sg_set_buf(&src_tab[0], km_sig, key_len);
    sg_set_buf(&src_tab[1], hash, hash_len);

    akcipher_request_set_crypt(req, src_tab, NULL, key_len,
                               hash_len);

    ret = crypto_akcipher_verify(req);
    if (ret) {
        pr_err("error: crypto_akcipher_verify returned: %d\n", ret);
        goto test_pkcs1_end;
    }

    memset(dec, 0, key_len + 1);
    ret = wc_RsaSSL_Verify(km_sig, key_len, dec, key_len, key);
    if (ret <= 0) {
        pr_err("error: wc_RsaSSL_Verify returned: %d\n", ret);
        goto test_pkcs1_end;
    }

    n_diff = memcmp(km_sig, sig, sig_len);
    if (n_diff) {
        pr_err("error: km-sig doesn't match sig: %d\n", n_diff);
        goto test_pkcs1_end;
    }

    /* dec and enc should match now. */
    n_diff = memcmp(dec, enc, enc_len);
    if (n_diff) {
        pr_err("error: decrypt doesn't match plain: %d\n", n_diff);
        goto test_pkcs1_end;
    }

    test_rc = 0;
test_pkcs1_end:
    if (req) { akcipher_request_free(req); req = NULL; }
    if (tfm) { crypto_free_akcipher(tfm); tfm = NULL; }

    if (init_rng) { wc_FreeRng(&rng); init_rng = 0; }
    if (init_key) { wc_FreeRsaKey(key); init_key = 0; }

    if (key) { free(key); key = NULL; }
    if (priv) { free(priv); priv = NULL; }
    if (pub) { free(pub); pub = NULL; }

    #ifdef WOLFKM_DEBUG_RSA
    pr_info("info: %s, %d, %d: self test returned: %d\n", driver,
            nbits, key_len, ret);
    #endif /* WOLFKM_DEBUG_RSA */

    return test_rc;
}
#endif /* WOLFSSL_KEY_GEN */

#ifdef WOLFKM_DEBUG_RSA_VERBOSE
static void km_rsa_dump_hex(const char * what, const byte * data,
                            word32 data_len)
{
    size_t i = 0;
    char   hex_str[32 + 1];
    size_t len = data_len;

    if (what && *what) {
        pr_info("%s: %d", what, data_len);
    }

    while (len) {
        memset(hex_str, 0, sizeof(hex_str));

        for (i = 0; i < 8 && len > 0; ++i, --len) {
            sprintf(hex_str + (i * 4), "%02x, ", data[data_len - len]);
        }

        pr_info("%s\n", hex_str);
    }

    pr_info("\n");

    return;
}
#endif /* WOLFKM_DEBUG_RSA_VERBOSE */
#endif /* !NO_RSA &&
        * (LINUXKM_LKCAPI_REGISTER_ALL || LINUXKM_LKCAPI_REGISTER_RSA)
        */
