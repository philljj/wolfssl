/* lkcapi_rsa.c -- glue logic to register RSA wolfCrypt implementations with
 * the Linux Kernel Cryptosystem
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
    #error lkcapi_rsa.c included in non-LINUXKM_LKCAPI_REGISTER project.
#endif

#if !defined(NO_RSA) && \
    (defined(LINUXKM_LKCAPI_REGISTER_ALL) || \
     defined(LINUXKM_LKCAPI_REGISTER_RSA))

#include <wolfssl/wolfcrypt/rsa.h>

#define WOLFKM_RSA_NAME      "rsa"
#define WOLFKM_RSA_DRIVER    ("rsa" WOLFKM_DRIVER_SUFFIX)

struct km_RsaCtx {
    WC_RNG   rng; /* needed for padding */
    byte     block_enc[256]; /* Large enough for RSA 2048. */
    byte     block_dec[256];
    RsaKey * key;
};

static int linuxkm_test_rsa(void)
{
    int                       ret = 0;
    byte *                    enc = NULL;
    byte *                    enc2 = NULL;
    int                       enc_len = 0;
    int                       enc_ret = 0;
    int                       dec_ret = 0;
    struct crypto_akcipher *  tfm = NULL;
    struct akcipher_request * req = NULL;
    RsaKey *                  key = NULL;
    WC_RNG                    rng;
    int                       bits = 2048;
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
    byte                      dec[32];
    byte                      dec2[32];
    int                       dec_len = 32;
    int                       n_diff = 0;
    struct scatterlist        src, dst;

    memset(dec, 0, sizeof(dec));
    memset(dec2, 0, sizeof(dec));

    sg_init_one(&src, dec2, sizeof(p_vector));
    sg_init_one(&dst, enc2, sizeof(p_vector));

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

    ret = wc_MakeRsaKey(key, bits, WC_RSA_EXPONENT, &rng);
    if (ret) {
        pr_err("error: make rsa key returned: %d\n", ret);
        goto test_rsa_end;
    }

    enc_len = wc_RsaEncryptSize(key);
    if (enc_len <= 0) {
        pr_err("error: rsa encrypt size returned: %d\n", enc_len);
        goto test_rsa_end;
    }

    enc = (byte*)malloc(enc_len);
    if (enc == NULL) {
        pr_err("error: allocating crypt(%d) failed\n", enc_len);
        goto test_rsa_end;
    }

    enc2 = (byte*)malloc(enc_len);
    if (enc2 == NULL) {
        pr_err("error: allocating crypt(%d) failed\n", enc_len);
        goto test_rsa_end;
    }

    enc_ret = wc_RsaPublicEncrypt(p_vector, sizeof(p_vector), enc,
                                    enc_len, key, &rng);

    if (enc_ret != enc_len) {
        pr_err("error: rsa pub enc returned: %d\n", enc_ret);
        goto test_rsa_end;
    }

    dec_ret = wc_RsaPrivateDecrypt(enc, enc_len, dec,
                                       dec_len, key);

    if (dec_ret != dec_len) {
        pr_err("error: rsa priv dec returned: %d\n", dec_ret);
        goto test_rsa_end;
    }

    n_diff = memcmp(dec, p_vector, sizeof(p_vector));
    if (n_diff) {
        pr_err("error: decrypt doesn't match plain: %d\n", n_diff);
        goto test_rsa_end;
    }

    /* get rsa priv der */
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

    tfm = crypto_alloc_akcipher(WOLFKM_RSA_NAME, 0, 0);
    if (IS_ERR(tfm)) {
        pr_err("error: allocating akcipher algorithm %s failed: %ld\n",
               WOLFKM_RSA_DRIVER, PTR_ERR(tfm));
        goto test_rsa_end;
    }

    req = akcipher_request_alloc(tfm, GFP_KERNEL);
    if (IS_ERR(req)) {
        pr_err("error: allocating akcipher request %s failed\n",
               WOLFKM_RSA_DRIVER);
        goto test_rsa_end;
    }

    ret = crypto_akcipher_set_pub_key(tfm, pub, pub_len);
    if (ret) {
        pr_err("error: crypto_akcipher_set_pub_key returned: %d\n", ret);
        goto test_rsa_end;
    }

    ret = crypto_akcipher_set_priv_key(tfm, priv, priv_len);
    if (ret) {
        pr_err("error: crypto_akcipher_set_priv_key returned: %d\n", ret);
        goto test_rsa_end;
    }

    akcipher_request_set_crypt(req, &src, &dst, sizeof(p_vector),
                               sizeof(p_vector));

    ret = crypto_akcipher_encrypt(req);

    if (ret) {
        pr_err("error: crypto_akcipher_encrypt returned: %d\n", ret);
        goto test_rsa_end;
    }

    pr_info("info: rsa self test good\n");
test_rsa_end:
    if (req) { akcipher_request_free(req); req = NULL; }
    if (tfm) { crypto_free_akcipher(tfm); tfm = NULL; }

    if (init_rng) { wc_FreeRng(&rng); init_rng = 0; }
    if (init_key) { wc_FreeRsaKey(key); init_key = 0; }

    if (enc) { free(enc); enc = NULL; }
    if (enc2) { free(enc2); enc2 = NULL; }
    if (key) { free(key); key = NULL; }
    if (priv) { free(priv); priv = NULL; }
    if (pub) { free(pub); pub = NULL; }

    pr_info("info: rsa self test returned: %d\n", ret);
    return ret;
}

/**
 * RSA encrypt with public key.
 * */
static int km_RsaEnc(struct akcipher_request *req)
{
    struct crypto_akcipher * tfm = NULL;
    struct km_RsaCtx *       ctx = NULL;
    int                      err = 0;
    int                      enc_len = 0;

    tfm = crypto_akcipher_reqtfm(req);
    ctx = akcipher_tfm_ctx(tfm);

    enc_len = wc_RsaEncryptSize(ctx->key);
    if (unlikely(enc_len <= 0)) {
        pr_err("error: %s: rsa encrypt size returned: %d\n",
               WOLFKM_RSA_DRIVER, enc_len);
        return -EINVAL;
    }

    if (unlikely(req->src->length > sizeof(ctx->block_dec))) {
        pr_err("error: %s: req->src->length too long: %d\n",
               WOLFKM_RSA_DRIVER, req->src->length);
        return -EINVAL;
    }

    #if 0
    if (unlikely(req->src->length != (unsigned int) enc_len)) {
        pr_err("error: %s: got %d, expected %d\n",
               WOLFKM_RSA_DRIVER, req->src->length, enc_len);
        return -EINVAL;
    }
    #endif

    scatterwalk_map_and_copy(ctx->block_dec, req->src, 0, req->src->length, 0);
    memset(ctx->block_enc, 0, sizeof(ctx->block_enc));

    err = wc_RsaPublicEncrypt(ctx->block_dec, enc_len, ctx->block_enc,
                              enc_len, ctx->key, &ctx->rng);

    if (unlikely(err)) {
        pr_err("error: %s: rsa pub enc returned: %d\n", WOLFKM_RSA_DRIVER,
        err);
    }

    return err;
}

/**
 * RSA decrypt with public key.
 * */
static int km_RsaDec(struct akcipher_request *req)
{
    struct crypto_akcipher * tfm = NULL;
    struct km_RsaCtx *       ctx = NULL;

    tfm = crypto_akcipher_reqtfm(req);
    ctx = akcipher_tfm_ctx(tfm);

    return 0;
}

/**
 * Decodes and sets the RSA private key.
 *
 * param tfm     the crypto_akcipher transform
 * param key     BER encoded private key and parameters
 * param keylen  key length
 * */
static int km_RsaSetPrivKey(struct crypto_akcipher *tfm, const void *key,
                            unsigned int keylen)
{
    int                err = 0;
    struct km_RsaCtx * ctx = NULL;
    word32             idx = 0;

    ctx = akcipher_tfm_ctx(tfm);

    err = wc_RsaPrivateKeyDecode(key, &idx, ctx->key, keylen);

    if (unlikely(err)) {
        if (!disable_setkey_warnings) {
            pr_err("%s: wc_RsaPrivateKeyDecode failed: %d\n",
                   WOLFKM_RSA_DRIVER, err);
        }
        return -EINVAL;
    }

    return err;
}

/**
 * Decodes and sets the RSA pub key.
 *
 * param tfm     the crypto_akcipher transform
 * param key     BER encoded pub key and parameters
 * param keylen  key length
 * */
static int km_RsaSetPubKey(struct crypto_akcipher *tfm, const void *key,
                           unsigned int keylen)
{
    int                err = 0;
    struct km_RsaCtx * ctx = NULL;
    word32             idx = 0;

    ctx = akcipher_tfm_ctx(tfm);

    err = wc_RsaPublicKeyDecode(key, &idx, ctx->key, keylen);

    if (unlikely(err)) {
        if (!disable_setkey_warnings) {
            pr_err("%s: wc_RsaPublicKeyDecode failed: %d\n",
                   WOLFKM_RSA_DRIVER, err);
        }
        return -EINVAL;
    }

    return err;
}

/**
 * Returns dest buffer size required for key.
 * */
static unsigned int km_RsaMax_size(struct crypto_akcipher *tfm)
{
    struct km_RsaCtx * ctx = NULL;

    ctx = akcipher_tfm_ctx(tfm);

    return 0;
}

/**
 * Init the rsa ctx. The RNG is needed for padding
 * and blinding.
 * */
static int km_RsaInit(struct crypto_akcipher *tfm)
{
    struct km_RsaCtx * ctx = NULL;
    int                ret = 0;

    ctx = akcipher_tfm_ctx(tfm);
    memset(ctx, 0, sizeof(struct km_RsaCtx));

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

    ret = wc_RsaSetRNG(ctx->key, &ctx->rng);
    if (ret) {
        pr_err("%s: rsa set rng returned: %d\n", WOLFKM_RSA_DRIVER, ret);
        return MEMORY_E;
    }

    return 0;
}

static void km_RsaExit(struct crypto_akcipher *tfm)
{
    struct km_RsaCtx * ctx = NULL;

    ctx = akcipher_tfm_ctx(tfm);

    if (ctx->key) {
        wc_FreeRsaKey(ctx->key);
        free(ctx->key);
        ctx->key = NULL;
    }

    wc_FreeRng(&ctx->rng);

    return;
}

static struct akcipher_alg rsaAlg = {
    .base.cra_name        = WOLFKM_RSA_NAME,
    .base.cra_driver_name = WOLFKM_RSA_DRIVER,
    .base.cra_priority    = WOLFSSL_LINUXKM_LKCAPI_PRIORITY,
    .base.cra_module      = THIS_MODULE,
    .base.cra_ctxsize     = sizeof(struct km_RsaCtx),
    .encrypt              = km_RsaEnc,
    .decrypt              = km_RsaDec,
    .set_priv_key         = km_RsaSetPrivKey,
    .set_pub_key          = km_RsaSetPubKey,
    .max_size             = km_RsaMax_size,
    .init                 = km_RsaInit,
    .exit                 = km_RsaExit,
};

static int rsaAlg_loaded = 0;
#endif /* !NO_RSA &&
        * (LINUXKM_LKCAPI_REGISTER_ALL || LINUXKM_LKCAPI_REGISTER_RSA)
        */
