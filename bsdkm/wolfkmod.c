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

#if defined(BSDKM_CRYPTO_REGISTER)
    #include <wolfssl/wolfcrypt/aes.h>
#endif

MALLOC_DEFINE(M_WOLFSSL, "libwolfssl", "wolfSSL kernel memory");

static int wolfkmod_init(void);
static int wolfkmod_cleanup(void);

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

    /**
     * todo: register wolfcrypt algs here with crypto_get_driverid
     * and related.
     * */

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
static int wolfkmod_load(void);
static int wolfkmod_unload(void);

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
/* libwolf device driver software context. */
struct libwolf_softc {
    int32_t driver_id;
};

struct km_aes_ctx {
    Aes * aes_encrypt;
    Aes * aes_decrypt;
};

typedef struct km_aes_ctx km_aes_ctx;

struct libwolf_session {
    km_aes_ctx aes_ctx;
    int32_t    driver_id;
    int        type;
    int        ivlen;
    int        klen;
};

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

static void libwolf_aes_ctx_reset(km_aes_ctx * ctx)
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
    pr_info("info: exiting km_AesExitCommon\n");
    #endif /* WOLFKM_DEBUG_AES */
}

static void libwolf_identify(driver_t * driver, device_t parent)
{
    (void)driver;

    /* don't double add libwolf child. */
    if (device_find_child(parent, "libwolf", -1) != NULL) {
        return;
    }

    BUS_ADD_CHILD(parent, 10, "libwolf", -1);
}

static int libwolf_probe(device_t dev)
{
    device_set_desc(dev, "wolfSSL crypto");
    return (BUS_PROBE_DEFAULT);
}

static int libwolf_attach(device_t dev)
{
    struct libwolf_softc * softc = NULL;
    int flags = CRYPTOCAP_F_SOFTWARE | CRYPTOCAP_F_SYNC;
    int ret = 0;

    ret = wolfkmod_init();
    if (ret != 0) {
        return (ECANCELED);
    }

    softc = device_get_softc(dev);

    softc->driver_id = crypto_get_driverid(dev, sizeof(struct libwolf_session),
                                           flags);
    if (softc->driver_id < 0) {
        printf("error: libwolf: crypto_get_driverid failed: %d\n",
               softc->driver_id);
        return (ENXIO);
    }

    printf("info: libwolf driver loaded\n");

    return (0);
}

static int libwolf_detach(device_t dev)
{
    struct libwolf_softc * softc = NULL;
    int ret = 0;

    ret = wolfkmod_cleanup();

    if (ret == 0) {
        /* unregister wolfcrypt algs */
        softc = device_get_softc(dev);

        if (softc->driver_id > 0) {
            crypto_unregister_all(softc->driver_id);
            softc->driver_id = 0;
        }
    }

    if (ret == 0) {
        printf("info: libwolf driver unloaded\n");
    }

    return (0);
}

static int libwolf_probesession(device_t dev,
                                const struct crypto_session_params *csp)
{
    struct libwolf_softc * softc = NULL;

    softc = device_get_softc(dev);

    (void)softc;
    (void)csp;
    return (EINVAL);
}

static int libwolf_newsession_aead(struct libwolf_session * session,
                                   const struct crypto_session_params *csp)
{
    int error = 0;
    int klen = csp->csp_cipher_klen * 8; /* key len in bytes */

    if (csp->csp_cipher_alg != CRYPTO_AES_NIST_GCM_16) {
        return (EOPNOTSUPP);
    }

    session->type = CRYPTO_AES_NIST_GCM_16;

    if (klen != 16 && klen != 24 && klen != 32) {
        printf("info: libwolf: newsession_aead: invalid klen: %d\n", klen);
        return (EINVAL);
    }

    session->klen = klen;
    session->ivlen = csp->csp_ivlen;

    session->aes_ctx.aes_encrypt = (Aes *)XMALLOC(sizeof(Aes), NULL,
                                          DYNAMIC_TYPE_AES);

    if (session->aes_ctx.aes_encrypt == NULL) {
        error = ENOMEM;
        printf("error: libwolf: newsession_aead: aes_encrypt alloc failed\n");
        goto newsession_aead_out;
    }

    error = wc_AesInit(session->aes_ctx.aes_encrypt, NULL, INVALID_DEVID);

newsession_aead_out:

    if (error != 0) {
        libwolf_aes_ctx_reset(&session->aes_ctx);
    }

    return (error);
}

static int libwolf_newsession(device_t dev, crypto_session_t cses,
                              const struct crypto_session_params *csp)
{
    struct libwolf_session * session = NULL;
    int error = 0;

    /* get the libwolf_session context */
    session = crypto_get_driver_session(cses);

    switch (csp->csp_mode) {
    case CSP_MODE_DIGEST:
    case CSP_MODE_CIPHER:
    case CSP_MODE_ETA:
        printf("info: libwolf: not supported: %d\n", csp->csp_mode);
        error = EOPNOTSUPP;
        break;
    case CSP_MODE_AEAD:
        error = libwolf_newsession_aead(session, csp);
        break;
    default:
        __assert_unreachable();
    }

    (void)dev;

    if (error) {
        printf("error: libwolf: newsession: %d\n", error);
    }

    //return (error);
    return (0);
}

/*
 *
 */
static void
libwolf_freesession(device_t dev, crypto_session_t cses)
{
    struct libwolf_session * session = NULL;

    /* get the libwolf_session context */
    session = crypto_get_driver_session(cses);

    libwolf_aes_ctx_reset(&session->aes_ctx);

    (void)dev;
    return;
}

static int libwolf_process(device_t dev, struct cryptop *crp, int hint)
{
    const struct crypto_session_params *csp;
    struct libwolf_session * session = NULL;
    int error = 0;

    session = crypto_get_driver_session(crp->crp_session);
    csp = crypto_get_params(crp->crp_session);

    (void)dev;
    (void)hint;
    (void)csp;
    (void)session;

    return error;
}

/* libwolf device driver */
static device_method_t libwolf_methods[] = {
    /* device interface methods */
    DEVMETHOD(device_identify, libwolf_identify),
    DEVMETHOD(device_probe, libwolf_probe),
    DEVMETHOD(device_attach, libwolf_attach),
    DEVMETHOD(device_detach, libwolf_detach),

    /* crypto device methods */
    DEVMETHOD(cryptodev_probesession, libwolf_probesession),
    DEVMETHOD(cryptodev_newsession, libwolf_newsession),
    DEVMETHOD(cryptodev_freesession, libwolf_freesession),
    DEVMETHOD(cryptodev_process, libwolf_process),

    DEVMETHOD_END
};

static driver_t libwolf_driver = {
    .name = "libwolf",
    .methods = libwolf_methods,
    .size = sizeof(struct libwolf_softc),
};

/* note: on x86, software-only drivers usually attach to nexus bus. */
DRIVER_MODULE(libwolfssl, nexus, libwolf_driver, NULL, NULL);
#endif /* BSDKM_CRYPTO_REGISTER */

#if !defined(BSDKM_CRYPTO_REGISTER)
static moduledata_t libwolfmod = {
    "libwolfssl",   /* module name */
    wolfkmod_event, /* module event handler */
    NULL            /* extra data, unused */
};

DECLARE_MODULE(libwolfssl, libwolfmod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
#endif /* !BSDKM_CRYPTO_REGISTER */

MODULE_VERSION(libwolfssl, 1);
#endif /* WOLFSSL_BSDKM */
