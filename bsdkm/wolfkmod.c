/* wolfkmod.c -- wolfssl FreeBSD kernel module.
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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

#ifdef WOLFSSL_BSDKM

/* freebsd system includes */
#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>

#if defined(BSDKM_CRYPTO_REGISTER)
    #include <opencrypto/cryptodev.h>
    #include <sys/bus.h>
    #include "cryptodev_if.h"
#endif

/* wolf includes */
#include <wolfssl/wolfcrypt/libwolfssl_sources.h>
#ifdef WOLFCRYPT_ONLY
    #include <wolfssl/version.h>
#else
    #include <wolfssl/ssl.h>
#endif
#if !defined(NO_CRYPT_TEST)
    #include <wolfcrypt/test/test.h>
#endif

MALLOC_DEFINE(M_WOLFSSL, "libwolfssl", "wolfSSL kernel memory");

#if defined(BSDKM_CRYPTO_REGISTER)
    #include "bsdkm/wolfkmod_aes.c"
#endif

/* common functions. */
static int  wolfkmod_init(void);
static int  wolfkmod_cleanup(void);
#if !defined(BSDKM_CRYPTO_REGISTER)
/* functions specific to a pure kernel module library build. */
static int  wolfkmod_load(void);
static int  wolfkmod_unload(void);
#else
/* functions specific to a kernel crypto driver module build. */
static void wolfkdriv_identify(driver_t * driver, device_t parent);
static int  wolfkdriv_probe(device_t dev);
static int  wolfkdriv_attach(device_t dev);
static int  wolfkdriv_detach(device_t dev);
static int  wolfkdriv_probesession(device_t dev,
                                   const struct crypto_session_params *csp);
static int  wolfkdriv_newsession(device_t dev, crypto_session_t cses,
                                 const struct crypto_session_params *csp);
static void wolfkdriv_freesession(device_t dev, crypto_session_t cses);
static int  wolfkdriv_process(device_t dev, struct cryptop *crp, int hint);
#endif /* !BSDKM_CRYPTO_REGISTER */

static int wolfkmod_init(void)
{
    int ret = 0;

    #ifdef WOLFCRYPT_ONLY
    ret = wolfCrypt_Init();
    if (ret != 0) {
        printf("error: wolfCrypt_Init failed: %s\n", wc_GetErrorString(ret));
        return (ECANCELED);
    }
    #else
    ret = wolfSSL_Init();
    if (ret != WOLFSSL_SUCCESS) {
        printf("error: wolfSSL_Init failed: %s\n", wc_GetErrorString(ret));
        return (ECANCELED);
    }
    #endif

    #ifndef NO_CRYPT_TEST
    ret = wolfcrypt_test(NULL);
    if (ret != 0) {
        printf("error: wolfcrypt test failed with return code: %d\n", ret);
        (void)wolfkmod_cleanup();
        return (ECANCELED);
    }
    #if defined(WOLFSSL_BSDKM_VERBOSE_DEBUG)
    printf("info: wolfCrypt self-test passed.\n");
    #endif /* WOLFSSL_BSDKM_VERBOSE_DEBUG */
    #endif /* NO_CRYPT_TEST */

    return (0);
}

static int wolfkmod_cleanup(void)
{
    int ret = 0;

    #ifdef WOLFCRYPT_ONLY
    ret = wolfCrypt_Cleanup();
    if (ret != 0) {
        printf("error: wolfCrypt_Cleanup failed: %s\n", wc_GetErrorString(ret));
        return (ECANCELED);
    }
    #else
    ret = wolfSSL_Cleanup();
    if (ret != WOLFSSL_SUCCESS) {
        printf("error: wolfSSL_Cleanup failed: %s\n", wc_GetErrorString(ret));
        return (ECANCELED);
    }
    #endif /* WOLFCRYPT_ONLY */

    #if defined(WOLFSSL_BSDKM_VERBOSE_DEBUG)
    printf("info: libwolfssl " LIBWOLFSSL_VERSION_STRING " cleanup complete.\n");
    #endif /* WOLFSSL_BSDKM_VERBOSE_DEBUG */

    return (0);
}

#if !defined(BSDKM_CRYPTO_REGISTER)
static int wolfkmod_load(void)
{
    int ret = 0;

    ret = wolfkmod_init();
    if (ret != 0) {
        return (ECANCELED);
    }

    printf("info: libwolfssl loaded\n");

    return (0);
}

static int wolfkmod_unload(void)
{
    int ret = 0;

    ret = wolfkmod_cleanup();

    if (ret == 0) {
        printf("info: libwolfssl unloaded\n");
    }

    return (ret);
}

/* see /usr/include/sys/module.h for more info. */
static int
wolfkmod_event(struct module * m, int what, void * arg)
{
    int ret = 0;

    switch (what) {
    case MOD_LOAD:
        ret = wolfkmod_load();
        break;
    case MOD_UNLOAD:
        ret = wolfkmod_unload();
        break;
    case MOD_SHUTDOWN:
    case MOD_QUIESCE:
    default:
        #if defined(WOLFSSL_BSDKM_VERBOSE_DEBUG)
        printf("info: not implemented: %d\n", what);
        #endif /* WOLFSSL_BSDKM_VERBOSE_DEBUG */
        ret = EOPNOTSUPP;
    }

    (void)m;
    (void)arg;

    return (ret);
}
#endif /* !BSDKM_CRYPTO_REGISTER */

#if defined(BSDKM_CRYPTO_REGISTER)
/* wolfkdriv device driver software context. */
struct wolfkdriv_softc {
    int32_t  crid;
    device_t dev;
};

struct km_aes_ctx {
    Aes * aes_encrypt;
    Aes * aes_decrypt;
};

typedef struct km_aes_ctx km_aes_ctx;

struct wolfkdriv_session {
    km_aes_ctx aes_ctx;
    int32_t    crid;
    int        type;
    int        ivlen;
    int        klen;
};

typedef struct wolfkdriv_session wolfkdriv_session_t;

static void km_AesFree(Aes * * aes) {
    if ((! aes) || (! *aes)) {
        return;
    }
    wc_AesFree(*aes);
    #if defined(HAVE_FIPS) && FIPS_VERSION3_LT(6,0,0)
    ForceZero(*aes, sizeof(**aes));
    #endif
    XFREE(*aes, NULL, DYNAMIC_TYPE_AES);
    *aes = NULL;
}

static void wolfkdriv_aes_ctx_reset(km_aes_ctx * ctx)
{
    if (ctx != NULL) {
        if (ctx->aes_encrypt) {
            km_AesFree(&ctx->aes_encrypt);
        }
        if (ctx->aes_decrypt) {
            km_AesFree(&ctx->aes_decrypt);
        }
    }

    #ifdef WOLFKM_DEBUG_AES
    printf("info: exiting km_AesExitCommon\n");
    #endif /* WOLFKM_DEBUG_AES */
}

static void wolfkdriv_identify(driver_t * driver, device_t parent)
{
    (void)driver;

    /* don't double add wolfkdriv child. */
    if (device_find_child(parent, "libwolf", -1) != NULL) {
        return;
    }

    BUS_ADD_CHILD(parent, 10, "libwolf", -1);
}

static int wolfkdriv_probe(device_t dev)
{
    device_set_desc(dev, "wolfSSL crypto");
    return (BUS_PROBE_DEFAULT);
}

/*
 * unregister libwolfssl crypto driver
 */
static void wolfkdriv_unregister(struct wolfkdriv_softc * softc)
{
    if (softc && softc->crid >= 0) {
        crypto_unregister_all(softc->crid);
        device_printf(softc->dev, "info: crid unregistered: %d\n", softc->crid);
        softc->crid = -1;
    }

    return;
}

static int wolfkdriv_attach(device_t dev)
{
    struct wolfkdriv_softc * softc = NULL;
    int flags = CRYPTOCAP_F_SOFTWARE | CRYPTOCAP_F_SYNC;
    int ret = 0;
    int crid = 0;
    int error = 0;

    ret = wolfkmod_init();
    if (ret != 0) {
        return (ECANCELED);
    }

    /**
     * register wolfcrypt algs here with crypto_get_driverid.
     *
     * The crid is the literal index into the kernel crypto_drivers array:
     *   - crid >= 0 is valid.
     *   - crid <  0 is error.
     * */
    softc = device_get_softc(dev);
    softc->dev = dev;

    softc->crid = crypto_get_driverid(dev, sizeof(wolfkdriv_session_t),
                                           flags);
    if (softc->crid < 0) {
        device_printf(dev, "error: crypto_get_driverid failed: %d\n",
               softc->crid);
        return (ENXIO);
    }

    /*
     * various sanity checks
     */

    /* 1. we should find ourself by name */
    crid = crypto_find_driver("libwolf");

    if (crid != softc->crid) {
        device_printf(dev, "error: attach: got crid %d, expected %d\n", crid,
               softc->crid);
        error = ENXIO;
        goto attach_out;
    }

    /* 2. test various algs */
    error = wolfkdriv_test_aes(dev, crid);

    if (error) {
        device_printf(dev, "error: attach: test_aes: %d\n", error);
        error = ENXIO;
        goto attach_out;
    }

    device_printf(dev, "info: driver loaded: %d\n", crid);

    #if defined(WOLFSSL_BSDKM_VERBOSE_DEBUG)
    device_printf(dev, "info: exiting attach\n");
    #endif /* WOLFSSL_BSDKM_VERBOSE_DEBUG */

attach_out:
    if (error) {
        wolfkdriv_unregister(softc);
        error = ENXIO;
    }

    return (error);
}

static int wolfkdriv_detach(device_t dev)
{
    struct wolfkdriv_softc * softc = NULL;
    int ret = 0;

    ret = wolfkmod_cleanup();

    if (ret == 0) {
        /* unregister wolfcrypt algs */
        softc = device_get_softc(dev);
        wolfkdriv_unregister(softc);
    }

    #if defined(WOLFSSL_BSDKM_VERBOSE_DEBUG)
    device_printf(dev, "info: exiting detach\n");
    #endif /* WOLFSSL_BSDKM_VERBOSE_DEBUG */

    return (0);
}

static int wolfkdriv_probesession(device_t dev,
                                  const struct crypto_session_params *csp)
{
    struct wolfkdriv_softc * softc = NULL;
    int error = CRYPTODEV_PROBE_ACCEL_SOFTWARE;

    softc = device_get_softc(dev);

    switch (csp->csp_mode) {
    case CSP_MODE_CIPHER:
        switch (csp->csp_cipher_alg) {
        case CRYPTO_AES_CBC:
            break;
        default:
            device_printf(dev, "info: not supported: %d\n", csp->csp_mode);
            error = EINVAL;
            break;
        }
        break;

    case CSP_MODE_AEAD:
        switch (csp->csp_cipher_alg) {
        case CRYPTO_AES_NIST_GCM_16:
            break;
        default:
            device_printf(dev, "info: not supported: %d\n", csp->csp_mode);
            error = EINVAL;
            break;
        }
        break;
    case CSP_MODE_DIGEST:
    case CSP_MODE_ETA:
    default:
        device_printf(dev, "info: not supported: %d\n", csp->csp_mode);
        error = EINVAL;
        break;
    }

    (void)softc;
    (void)csp;

    #if defined(WOLFSSL_BSDKM_VERBOSE_DEBUG)
    device_printf(dev, "info: exiting probesession\n");
    #endif /* WOLFSSL_BSDKM_VERBOSE_DEBUG */
    return (error);
}

static int wolfkdriv_newsession_cipher(device_t dev,
                                       wolfkdriv_session_t * session,
                                       const struct crypto_session_params *csp)
{
    int error = 0;
    int klen = csp->csp_cipher_klen; /* key len in bytes */

    switch (csp->csp_cipher_alg) {
    case CRYPTO_AES_NIST_GCM_16:
        session->type = CRYPTO_AES_NIST_GCM_16;
        break;
    case CRYPTO_AES_CBC:
        session->type = CRYPTO_AES_CBC;
        break;
    default:
        return (EOPNOTSUPP);
    }

    if (klen != 16 && klen != 24 && klen != 32) {
        device_printf(dev, "info: newsession_cipher: invalid klen: %d\n", klen);
        return (EINVAL);
    }

    session->klen = klen;
    session->ivlen = csp->csp_ivlen;
    session->aes_ctx.aes_encrypt = (Aes *)XMALLOC(sizeof(Aes), NULL,
                                          DYNAMIC_TYPE_AES);

    if (session->aes_ctx.aes_encrypt == NULL) {
        error = ENOMEM;
        device_printf(dev, "error: newsession_cipher: alloc failed\n");
        goto newsession_cipher_out;
    }

    error = wc_AesInit(session->aes_ctx.aes_encrypt, NULL, INVALID_DEVID);
    if (error) {
        device_printf(dev, "error: newsession_cipher: aes init: %d\n", error);
        goto newsession_cipher_out;
    }

    error = wc_AesSetKey(session->aes_ctx.aes_encrypt, csp->csp_cipher_key,
                         csp->csp_cipher_klen, NULL, AES_ENCRYPTION);
    if (error) {
        device_printf(dev, "error: newsession_cipher: aes setkey: %d\n", error);
        goto newsession_cipher_out;
    }

newsession_cipher_out:

    if (error != 0) {
        wolfkdriv_aes_ctx_reset(&session->aes_ctx);
        return (EINVAL);
    }

    return (error);
}

static int wolfkdriv_newsession(device_t dev, crypto_session_t cses,
                              const struct crypto_session_params *csp)
{
    wolfkdriv_session_t * session = NULL;
    int error = 0;

    /* get the wolfkdriv_session_t context */
    session = crypto_get_driver_session(cses);

    switch (csp->csp_mode) {
    case CSP_MODE_DIGEST:
    case CSP_MODE_ETA:
        device_printf(dev, "info: not supported: %d\n", csp->csp_mode);
        error = EOPNOTSUPP;
        break;
    case CSP_MODE_CIPHER:
    case CSP_MODE_AEAD:
        error = wolfkdriv_newsession_cipher(dev, session, csp);
        break;
    default:
        __assert_unreachable();
    }

    (void)dev;

    if (error) {
        device_printf(dev, "error: newsession: %d\n", error);
    }

    #if defined(WOLFSSL_BSDKM_VERBOSE_DEBUG)
    device_printf(dev, "info: exiting newsession\n");
    #endif /* WOLFSSL_BSDKM_VERBOSE_DEBUG */

    //return (error);
    return (0);
}

/*
 *
 */
static void
wolfkdriv_freesession(device_t dev, crypto_session_t cses)
{
    wolfkdriv_session_t * session = NULL;
    (void)dev;

    /* get the wolfkdriv_session_t context */
    session = crypto_get_driver_session(cses);

    /* clean it up */
    wolfkdriv_aes_ctx_reset(&session->aes_ctx);

    #if defined(WOLFSSL_BSDKM_VERBOSE_DEBUG)
    device_printf(dev, "info: exiting freesession\n");
    #endif /* WOLFSSL_BSDKM_VERBOSE_DEBUG */
    return;
}

static int wolfkdriv_cipher_work(device_t dev, wolfkdriv_session_t * session,
                                 struct cryptop * crp,
                                 const struct crypto_session_params * csp)
{
    int error = 0;
    if (csp->csp_cipher_alg != CRYPTO_AES_CBC) {
        error = EINVAL;
    }

    (void)dev;
    (void)session;
    (void)crp;
    return (error);
}

static int wolfkdriv_process(device_t dev, struct cryptop * crp, int hint)
{
    const struct crypto_session_params * csp = NULL;
    wolfkdriv_session_t * session = NULL;
    int error = 0;

    session = crypto_get_driver_session(crp->crp_session);
    csp = crypto_get_params(crp->crp_session);

    (void)dev;
    (void)hint;

    switch (csp->csp_mode) {
    case CSP_MODE_CIPHER:
        error = wolfkdriv_cipher_work(dev, session, crp, csp);
        break;
    case CSP_MODE_DIGEST:
    case CSP_MODE_ETA:
    case CSP_MODE_AEAD:
        error = EINVAL;
        break;
    default:
        __assert_unreachable();
    }

    crp->crp_etype = error;
    crypto_done(crp);

    #if defined(WOLFSSL_BSDKM_VERBOSE_DEBUG)
    device_printf(dev, "info: process: mode=%d, cipher_alg=%d, error=%d\n",
                  csp->csp_mode, csp->csp_cipher_alg, error);
    #endif /* WOLFSSL_BSDKM_VERBOSE_DEBUG */

    return (error);
}

/*
 * wolfkmod as a crypto device driver.
 */
static device_method_t wolfkdriv_methods[] = {
    /* device interface methods: called during device setup, etc. */
    DEVMETHOD(device_identify, wolfkdriv_identify),
    DEVMETHOD(device_probe, wolfkdriv_probe),
    DEVMETHOD(device_attach, wolfkdriv_attach),
    DEVMETHOD(device_detach, wolfkdriv_detach),

    /* crypto device session methods: called during crypto session setup,
     * work, etc. */
    DEVMETHOD(cryptodev_probesession, wolfkdriv_probesession),
    DEVMETHOD(cryptodev_newsession, wolfkdriv_newsession),
    DEVMETHOD(cryptodev_freesession, wolfkdriv_freesession),
    DEVMETHOD(cryptodev_process, wolfkdriv_process),

    DEVMETHOD_END
};

static driver_t wolfkdriv_driver = {
    .name = "libwolf",
    .methods = wolfkdriv_methods,
    .size = sizeof(struct wolfkdriv_softc),
};

/* note: on x86, software-only drivers usually attach to nexus bus. */
DRIVER_MODULE(libwolfssl, nexus, wolfkdriv_driver, NULL, NULL);
#endif /* BSDKM_CRYPTO_REGISTER */

#if !defined(BSDKM_CRYPTO_REGISTER)
/*
 * wolfkmod as a pure kernel module.
 */
static moduledata_t libwolfmod = {
    "libwolfssl",   /* module name */
    wolfkmod_event, /* module event handler */
    NULL            /* extra data, unused */
};

DECLARE_MODULE(libwolfssl, libwolfmod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
#endif /* !BSDKM_CRYPTO_REGISTER */

MODULE_VERSION(libwolfssl, 1);
#endif /* WOLFSSL_BSDKM */
