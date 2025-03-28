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
    #error lkcapi_rsa.c included in non-LINUXKM_LKCAPI_REGISTER project.
#endif

#if !defined(NO_RSA) && \
    (defined(LINUXKM_LKCAPI_REGISTER_ALL) || \
     defined(LINUXKM_LKCAPI_REGISTER_RSA))

#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/rsa.h>

#define WOLFKM_RSA_NAME      "rsa"
#define WOLFKM_RSA_DRIVER    ("rsa" WOLFKM_DRIVER_SUFFIX)

struct km_RsaCtx {
    WC_RNG   rng; /* needed for padding */
    byte     block_enc[512]; /* Large enough for RSA 2048. */
    byte     block_dec[512];
    RsaKey * key;
};

/**
 * akcipher_alg callbacks
 * */
static int          km_RsaInit(struct crypto_akcipher *tfm);
static void         km_RsaExit(struct crypto_akcipher *tfm);
static int          km_RsaSign(struct akcipher_request *req);
static int          km_RsaVerify(struct akcipher_request *req);
static int          km_RsaEnc(struct akcipher_request *req);
static int          km_RsaDec(struct akcipher_request *req);
static int          km_RsaSetPrivKey(struct crypto_akcipher *tfm,
                                     const void *key, unsigned int keylen);
static int          km_RsaSetPubKey(struct crypto_akcipher *tfm,
                                    const void *key, unsigned int keylen);
static unsigned int km_RsaMaxSize(struct crypto_akcipher *tfm);

static struct akcipher_alg rsaAlg = {
    .base.cra_name        = WOLFKM_RSA_NAME,
    .base.cra_driver_name = WOLFKM_RSA_DRIVER,
    .base.cra_priority    = WOLFSSL_LINUXKM_LKCAPI_PRIORITY,
    .base.cra_module      = THIS_MODULE,
    .base.cra_ctxsize     = sizeof(struct km_RsaCtx),
    .sign                 = km_RsaSign,
    .verify               = km_RsaVerify,
    .encrypt              = km_RsaEnc,
    .decrypt              = km_RsaDec,
    .set_priv_key         = km_RsaSetPrivKey,
    .set_pub_key          = km_RsaSetPubKey,
    .max_size             = km_RsaMaxSize,
    .init                 = km_RsaInit,
    .exit                 = km_RsaExit,
};

static int  linuxkm_test_rsa_driver(const char * driver, int nbits);
static int  linuxkm_test_pkcs1_driver(const char * driver, int nbits);
#ifdef WOLFKM_DEBUG_RSA_VERBOSE
static void km_rsa_dump_hex(const char * what, const byte * data,
                            word32 data_len);
#endif /* WOLFKM_DEBUG_RSA_VERBOSE */


/**
 * Tests implemented below.
 * */

static int linuxkm_test_rsa(void)
{
    int rc = 0;

    /* test wolfcrypt RSA API vs wolfkm RSA driver. */
    rc = linuxkm_test_rsa_driver(WOLFKM_RSA_DRIVER, 2048);
    if (rc) { return rc; }

    rc = linuxkm_test_rsa_driver(WOLFKM_RSA_DRIVER, 3072);
    if (rc) { return rc; }

    #ifdef WOLFKM_DEBUG_RSA
    /* repeat test against stock linux RSA akcipher. */
    rc = linuxkm_test_rsa_driver("rsa-generic", 2048);
    if (rc) { return rc; }

    rc = linuxkm_test_rsa_driver("rsa-generic", 3072);
    if (rc) { return rc; }

    rc = linuxkm_test_pkcs1_driver("pkcs1pad(rsa-generic,sha256)", 2048);
    if (rc) { return rc; }
    #endif /* WOLFKM_DEBUG_RSA */

    return rc;
}

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
    word32                    encrypt_len = 0;
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

    encrypt_len = wc_RsaEncryptSize(key);
    if (encrypt_len <= 0) {
        pr_err("error: rsa encrypt size returned: %d\n", encrypt_len);
        goto test_rsa_end;
    }

    /**
     * Allocate buffers based on the RsaKey encrypt_len.
     *
     * Add +1 for dec and plaintext arrays to printf nicely.
     * */
    enc = (byte*)malloc(encrypt_len);
    if (enc == NULL) {
        pr_err("error: allocating enc(%d) failed\n", encrypt_len);
        goto test_rsa_end;
    }

    dec = (byte*)malloc(encrypt_len + 1);
    if (dec == NULL) {
        pr_err("error: allocating dec(%d) failed\n", encrypt_len);
        goto test_rsa_end;
    }

    plaintext = (byte*)malloc(encrypt_len + 1);
    if (plaintext == NULL) {
        pr_err("error: allocating plaintext(%d) failed\n", encrypt_len);
        goto test_rsa_end;
    }

    memset(enc,  0, encrypt_len);
    memset(dec,  0, encrypt_len + 1);
    memset(plaintext, 0, encrypt_len + 1);

    /* Fill up dec and plaintext with plaintext reference. */
    for (i = 0; i < encrypt_len / sizeof(p_vector); ++i) {
        memcpy(dec  + i * sizeof(p_vector), p_vector, sizeof(p_vector));
        memcpy(plaintext + i * sizeof(p_vector), p_vector, sizeof(p_vector));
    }

    /**
     * Sanity test: first encrypt and decrypt with direct wolfcrypt API.
     * */
    out_len = encrypt_len;
    enc_ret = wc_RsaDirect(dec, encrypt_len, enc, &out_len, key,
                           RSA_PUBLIC_ENCRYPT, &rng);
    if (enc_ret != (int) encrypt_len || encrypt_len != out_len) {
        pr_err("error: rsa pub enc returned: %d, %d\n", enc_ret, out_len);
        ret = -1;
        goto test_rsa_end;
    }

    km_rsa_dump_hex("enc", enc, encrypt_len);

    memset(dec, 0, encrypt_len);
    dec_ret = wc_RsaDirect(enc, encrypt_len, dec, &out_len, key,
                           RSA_PRIVATE_DECRYPT, &rng);
    if (dec_ret != (int) encrypt_len || encrypt_len != out_len) {
        pr_err("error: rsa priv dec returned: %d, %d\n", dec_ret, out_len);
        goto test_rsa_end;
    }

    /* dec and plaintext should match now. */
    n_diff = memcmp(dec, plaintext, encrypt_len);
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

    #ifdef WOLFKM_DEBUG_RSA_VERBOSE
    //km_rsa_dump_hex("pub", pub, pub_len);
    #endif /* WOLFKM_DEBUG_RSA_VERBOSE */

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
        if (maxsize != encrypt_len) {
            pr_err("error: crypto_akcipher_maxsize "
                   "returned %d, expected %d\n", maxsize, encrypt_len);
            goto test_rsa_end;
        }
    }

    /* kernel module encrypt */
    sg_init_one(&src, dec, encrypt_len);
    sg_init_one(&dst, enc, encrypt_len);

    akcipher_request_set_crypt(req, &src, &dst, encrypt_len, encrypt_len);

    ret = crypto_akcipher_encrypt(req);
    if (ret) {
        pr_err("error: crypto_akcipher_encrypt returned: %d\n", ret);
        goto test_rsa_end;
    }

    km_rsa_dump_hex("enc", enc, encrypt_len);
    memset(dec, 0, encrypt_len + 1);
    dec_ret = wc_RsaDirect(enc, encrypt_len, dec, &out_len, key,
                           RSA_PRIVATE_DECRYPT, &rng);

    if (dec_ret != (int) encrypt_len || encrypt_len != out_len) {
        pr_err("error: rsa priv dec returned: %d, %d\n", dec_ret, out_len);
        goto test_rsa_end;
    }

    n_diff = memcmp(dec, plaintext, encrypt_len);
    if (n_diff) {
        pr_err("error: decrypt doesn't match plain: %d\n", n_diff);
        goto test_rsa_end;
    }

    #ifdef WOLFKM_DEBUG_RSA_VERBOSE
    pr_info("info: %zu: %s\n", strlen((const char *)dec), dec);
    #endif /* WOLFKM_DEBUG_RSA_VERBOSE */

    /* kernel module decrypt with rsa private key */
    enc_ret = wc_RsaDirect(dec, encrypt_len, enc, &out_len, key,
                           RSA_PUBLIC_ENCRYPT, &rng);

    if (enc_ret != (int) encrypt_len || encrypt_len != out_len) {
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
        if (maxsize != encrypt_len) {
            pr_err("error: crypto_akcipher_maxsize "
                   "returned %d, expected %d\n", maxsize, encrypt_len);
            goto test_rsa_end;
        }
    }

    #ifdef WOLFKM_DEBUG_RSA_VERBOSE
    //km_rsa_dump_hex("priv", priv, priv_len);
    #endif /* WOLFKM_DEBUG_RSA_VERBOSE */

    sg_init_one(&src, enc, encrypt_len);
    sg_init_one(&dst, dec, encrypt_len);

    akcipher_request_set_crypt(req, &src, &dst, encrypt_len, encrypt_len);

    memset(dec, 0, encrypt_len);
    ret = crypto_akcipher_decrypt(req);
    if (ret) {
        pr_err("error: crypto_akcipher_decrypt returned: %d\n", ret);
        goto test_rsa_end;
    }

    n_diff = memcmp(dec, plaintext, encrypt_len);
    if (n_diff) {
        pr_err("error: decrypt doesn't match plain: %d\n", n_diff);
        goto test_rsa_end;
    }

    #ifdef WOLFKM_DEBUG_RSA_VERBOSE
    pr_info("info: %zu: %s\n", strlen((const char *)dec), dec);
    #endif /* WOLFKM_DEBUG_RSA_VERBOSE */

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
            nbits, encrypt_len, ret);
    #endif /* WOLFKM_DEBUG_RSA */

    return test_rc;
}

static int linuxkm_test_pkcs1_driver(const char * driver, int nbits)
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
    byte *                    sig = NULL;
    byte *                    dec = NULL;
    byte *                    enc = NULL;
    word32                    encrypt_len = 0;
    word32                    sig_len = 0;
    word32                    enc_len = 0;
    //word32                    out_len = 0;
    struct scatterlist        src, dst;
    struct scatterlist        src_tab[2];
    int                       n_diff = 0;

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

    encrypt_len = wc_RsaEncryptSize(key);
    if (encrypt_len <= 0) {
        pr_err("error: rsa encrypt size returned: %d\n", encrypt_len);
        goto test_pkcs1_end;
    }

    sig = (byte*)malloc(encrypt_len);
    if (sig == NULL) {
        pr_err("error: allocating sig(%d) failed\n", encrypt_len);
        goto test_pkcs1_end;
    }
    memset(sig, 0, encrypt_len);

    enc = (byte*)malloc(encrypt_len);
    if (enc == NULL) {
        pr_err("error: allocating enc(%d) failed\n", encrypt_len);
        goto test_pkcs1_end;
    }
    memset(enc, 0, encrypt_len);

    dec = (byte*)malloc(encrypt_len + 1);
    if (dec == NULL) {
        pr_err("error: allocating dec(%d) failed\n", encrypt_len);
        goto test_pkcs1_end;
    }
    memset(dec, 0, encrypt_len + 1);

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

    enc_len = wc_EncodeSignature(enc, p_vector, sizeof(p_vector), SHA256h);
    if (enc_len <= 0) {
        pr_err("error: wc_EncodeSignature returned: %d\n", enc_len);
        goto test_pkcs1_end;
    }

    sig_len = wc_RsaSSL_Sign(enc, enc_len, sig, encrypt_len, key, &rng);
    if (sig_len <= 0) {
        pr_err("error: wc_RsaSSL_Sign returned: %d\n", sig_len);
        goto test_pkcs1_end;
    }

    #ifdef WOLFKM_DEBUG_RSA_VERBOSE
    km_rsa_dump_hex("sig", sig, sig_len);
    #endif /* WOLFKM_DEBUG_RSA_VERBOSE */

    memset(dec, 0, encrypt_len + 1);
    ret = wc_RsaSSL_Verify(sig, encrypt_len, dec, enc_len, key);
    if (ret <= 0 || ret != enc_len) {
        pr_err("error: wc_RsaSSL_Verify returned %d, expected %zu\n" , ret,
               enc_len);
        goto test_pkcs1_end;
    }

    /* dec and p_vector should match now. */
    n_diff = memcmp(dec, enc, enc_len);
    if (n_diff) {
        pr_err("error: decrypt doesn't match plain: %d\n", n_diff);
        goto test_pkcs1_end;
    }

    #ifdef WOLFKM_DEBUG_RSA_VERBOSE
    pr_info("info: %zu: %s\n", strlen((const char *)dec), dec);
    #endif /* WOLFKM_DEBUG_RSA_VERBOSE */

    /**
     * Now allocate the akcipher transform, and set up
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
        if (maxsize != encrypt_len) {
            pr_err("error: crypto_akcipher_maxsize "
                   "returned %d, expected %d\n", maxsize, encrypt_len);
            goto test_pkcs1_end;
        }
    }

    sg_init_one(&src, p_vector, sizeof(p_vector));
    sg_init_one(&dst, sig, encrypt_len);
    memset(sig, 0, encrypt_len);

    akcipher_request_set_crypt(req, &src, &dst, sizeof(p_vector), encrypt_len);

    ret = crypto_akcipher_sign(req);
    if (ret) {
        pr_err("error: crypto_akcipher_sign returned: %d\n", ret);
        goto test_pkcs1_end;
    }

    #ifdef WOLFKM_DEBUG_RSA_VERBOSE
    km_rsa_dump_hex("sig", sig, encrypt_len);
    #endif /* WOLFKM_DEBUG_RSA_VERBOSE */

    /**
     * Set sig as src, and null as dst.
     * src_tab is:
     *   src_tab[0]: signature
     *   src_tab[1]: message (digest)
     *
     * src_len is sig size, dst_len is digest size. */
    sg_init_one(&src, sig, encrypt_len);
    sg_init_table(src_tab, 2);
    sg_set_buf(&src_tab[0], sig, encrypt_len);
    sg_set_buf(&src_tab[1], p_vector, sizeof(p_vector));

    akcipher_request_set_crypt(req, src_tab, NULL, encrypt_len, sizeof(p_vector));

    ret = crypto_akcipher_verify(req);
    if (ret) {
        pr_err("error: crypto_akcipher_verify returned: %d\n", ret);
        goto test_pkcs1_end;
    }

    memset(dec, 0, encrypt_len + 1);
    ret = wc_RsaSSL_Verify(sig, encrypt_len, dec, encrypt_len, key);
    if (ret <= 0) {
        pr_err("error: wc_RsaSSL_Verify returned: %d\n", ret);
        goto test_pkcs1_end;
    }

    #ifdef WOLFKM_DEBUG_RSA_VERBOSE
    pr_info("info: %zu: %s\n", strlen((const char *)dec), dec);
    #endif /* WOLFKM_DEBUG_RSA_VERBOSE */

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
            nbits, encrypt_len, ret);
    #endif /* WOLFKM_DEBUG_RSA */

    return test_rc;
}

/**
 * RSA encrypt with public key.
 *
 * Requires that crypto_akcipher_set_pub_key has been called first.
 *
 * returns 0   on success
 * returns < 0 on error 
 * */
static int km_RsaEnc(struct akcipher_request *req)
{
    struct crypto_akcipher * tfm = NULL;
    struct km_RsaCtx *       ctx = NULL;
    int                      err = 0;
    word32                   encrypt_len = 0;
    word32                   out_len = 0;

    if (req->src == NULL || req->dst == NULL) {
        pr_err("error: %s: rsa encrypt: null\n",
               WOLFKM_RSA_DRIVER);
        return -EINVAL;
    }

    tfm = crypto_akcipher_reqtfm(req);
    ctx = akcipher_tfm_ctx(tfm);

    encrypt_len = wc_RsaEncryptSize(ctx->key);
    if (unlikely(encrypt_len <= 0)) {
        pr_err("error: %s: rsa encrypt size returned: %d\n",
               WOLFKM_RSA_DRIVER, encrypt_len);
        return -EINVAL;
    }

    out_len = encrypt_len;

    if (unlikely(req->src->length != (unsigned int) encrypt_len)) {
        pr_err("error: %s: got %d, expected %d\n",
               WOLFKM_RSA_DRIVER, req->src->length, encrypt_len);
        return -EINVAL;
    }

    if (unlikely(req->dst->length != (unsigned int) encrypt_len)) {
        pr_err("error: %s: got %d, expected %d\n",
               WOLFKM_RSA_DRIVER, req->dst->length, encrypt_len);
        return -EINVAL;
    }

    /* copy req->src to ctx->block_dec */
    scatterwalk_map_and_copy(ctx->block_dec, req->src, 0, req->src->length, 0);
    memset(ctx->block_enc, 0, sizeof(ctx->block_enc));

    err = wc_RsaDirect(ctx->block_dec, encrypt_len, ctx->block_enc,
                       &out_len, ctx->key, RSA_PUBLIC_ENCRYPT, &ctx->rng);

    if (unlikely(err != (int) encrypt_len || encrypt_len != out_len)) {
        pr_err("error: %s: rsa pub enc returned: %d, %d, %d\n",
               WOLFKM_RSA_DRIVER, err, out_len, encrypt_len);
        return -EINVAL;
    }

    /* copy ctx->block_enc to req->dst */
    scatterwalk_map_and_copy(ctx->block_enc, req->dst, 0, encrypt_len, 1);

    #ifdef WOLFKM_DEBUG_RSA
    pr_info("info: exiting km_RsaEnc\n");
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
static int km_RsaDec(struct akcipher_request *req)
{
    struct crypto_akcipher * tfm = NULL;
    struct km_RsaCtx *       ctx = NULL;
    int                      err = 0;
    word32                   encrypt_len = 0;
    word32                   out_len = 0;

    if (req->src == NULL || req->dst == NULL) {
        pr_err("error: %s: rsa encrypt: null\n",
               WOLFKM_RSA_DRIVER);
        return -EINVAL;
    }

    tfm = crypto_akcipher_reqtfm(req);
    ctx = akcipher_tfm_ctx(tfm);

    encrypt_len = wc_RsaEncryptSize(ctx->key);
    if (unlikely(encrypt_len <= 0)) {
        pr_err("error: %s: rsa encrypt size returned: %d\n",
               WOLFKM_RSA_DRIVER, encrypt_len);
        return -EINVAL;
    }

    out_len = encrypt_len;

    if (unlikely(req->src->length != (unsigned int) encrypt_len)) {
        pr_err("error: %s: got %d, expected %d\n",
               WOLFKM_RSA_DRIVER, req->src->length, encrypt_len);
        return -EINVAL;
    }

    if (unlikely(req->dst->length != (unsigned int) encrypt_len)) {
        pr_err("error: %s: got %d, expected %d\n",
               WOLFKM_RSA_DRIVER, req->dst->length, encrypt_len);
        return -EINVAL;
    }

    /* copy req->src to ctx->block_dec */
    scatterwalk_map_and_copy(ctx->block_dec, req->src, 0, req->src->length, 0);
    memset(ctx->block_enc, 0, sizeof(ctx->block_enc));

    err = wc_RsaDirect(ctx->block_dec, encrypt_len, ctx->block_enc,
                       &out_len, ctx->key, RSA_PRIVATE_DECRYPT, &ctx->rng);

    if (unlikely(err != (int) encrypt_len || encrypt_len != out_len)) {
        pr_err("error: %s: rsa pub enc returned: %d, %d, %d\n",
               WOLFKM_RSA_DRIVER, err, out_len, encrypt_len);
        return -EINVAL;
    }

    /* copy ctx->block_enc to req->dst */
    scatterwalk_map_and_copy(ctx->block_enc, req->dst, 0, encrypt_len, 1);

    #ifdef WOLFKM_DEBUG_RSA
    pr_info("info: exiting km_RsaDec\n");
    #endif /* WOLFKM_DEBUG_RSA */
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

    #ifdef WOLFKM_DEBUG_RSA
    pr_info("info: exiting km_RsaSetPrivKey\n");
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

    #ifdef WOLFKM_DEBUG_RSA
    pr_info("info: exiting km_RsaSetPubKey\n");
    #endif /* WOLFKM_DEBUG_RSA */
    return err;
}

/**
 * Returns dest buffer size required for key.
 * */
static unsigned int km_RsaMaxSize(struct crypto_akcipher *tfm)
{
    struct km_RsaCtx * ctx = NULL;
    word32             encrypt_len = 0;

    ctx = akcipher_tfm_ctx(tfm);

    encrypt_len = wc_RsaEncryptSize(ctx->key);
    if (unlikely(encrypt_len <= 0)) {
        pr_err("error: %s: rsa encrypt size returned: %d\n",
               WOLFKM_RSA_DRIVER, encrypt_len);
        return -EINVAL;
    }

    #ifdef WOLFKM_DEBUG_RSA
    pr_info("info: exiting km_RsaMaxSize\n");
    #endif /* WOLFKM_DEBUG_RSA */
    return (unsigned int) encrypt_len;
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

    #ifdef WOLFKM_DEBUG_RSA
    pr_info("info: exiting km_RsaInit\n");
    #endif /* WOLFKM_DEBUG_RSA */
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

    #ifdef WOLFKM_DEBUG_RSA
    pr_info("info: exiting km_RsaExit\n");
    #endif /* WOLFKM_DEBUG_RSA */
    return;
}

static int km_RsaSign(struct akcipher_request *req)
{
    struct crypto_akcipher * tfm = NULL;
    struct km_RsaCtx *       ctx = NULL;

    if (req->src == NULL || req->dst == NULL) {
        pr_err("error: %s: rsa encrypt: null\n",
               WOLFKM_RSA_DRIVER);
        return -EINVAL;
    }

    tfm = crypto_akcipher_reqtfm(req);
    ctx = akcipher_tfm_ctx(tfm);

    return 0;
}

static int km_RsaVerify(struct akcipher_request *req)
{
    struct crypto_akcipher * tfm = NULL;
    struct km_RsaCtx *       ctx = NULL;

    if (req->src == NULL || req->dst == NULL) {
        pr_err("error: %s: rsa encrypt: null\n",
               WOLFKM_RSA_DRIVER);
        return -EINVAL;
    }

    tfm = crypto_akcipher_reqtfm(req);
    ctx = akcipher_tfm_ctx(tfm);

    return 0;
}

static int rsaAlg_loaded = 0;

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
