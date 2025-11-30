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

#if !defined(BSDKM_CRYPTO_REGISTER)
static int wolfkmod_init(void);
static int wolfkmod_cleanup(void);
static int wolfkmod_load(void);
static int wolfkmod_unload(void);

static int wolfkmod_init(void)
{
    int ret = 0;

    #ifdef WOLFCRYPT_ONLY
    ret = wolfCrypt_Init();
    if (ret != 0) {
        printf("error: wolfCrypt_Init failed: %s\n", wc_GetErrorString(ret));
        return -ECANCELED;
    }
    #else
    ret = wolfSSL_Init();
    if (ret != WOLFSSL_SUCCESS) {
        printf("error: wolfSSL_Init failed: %s\n", wc_GetErrorString(ret));
        return -ECANCELED;
    }
    #endif

    return ret;
}

static int wolfkmod_cleanup(void)
{
    int ret = 0;

    #ifdef WOLFCRYPT_ONLY
    ret = wolfCrypt_Cleanup();
    if (ret != 0) {
        printf("error: wolfCrypt_Cleanup failed: %s\n", wc_GetErrorString(ret));
    }
    else {
        #if defined(WOLFSSL_BSDKM_VERBOSE_DEBUG)
        printf("info: wolfCrypt " LIBWOLFSSL_VERSION_STRING " cleanup complete.\n");
        #endif /* WOLFSSL_BSDKM_VERBOSE_DEBUG */
    }
    #else
    ret = wolfSSL_Cleanup();
    if (ret != WOLFSSL_SUCCESS) {
        printf("error: wolfSSL_Cleanup failed: %s\n", wc_GetErrorString(ret));
    }
    else {
        #if defined(WOLFSSL_BSDKM_VERBOSE_DEBUG)
        printf("info: wolfSSL " LIBWOLFSSL_VERSION_STRING " cleanup complete.\n");
        #endif /* WOLFSSL_BSDKM_VERBOSE_DEBUG */
    }
    #endif

    return ret;
}

static int wolfkmod_load(void)
{
    int ret = 0;

    ret = wolfkmod_init();
    if (ret != 0) {
        return -ECANCELED;
    }

    #ifndef NO_CRYPT_TEST
    ret = wolfcrypt_test(NULL);
    if (ret != 0) {
        printf("error: wolfcrypt test failed with return code: %d\n", ret);
        (void)wolfkmod_cleanup();
        return -ECANCELED;
    }
    else {
        #if defined(WOLFSSL_BSDKM_VERBOSE_DEBUG)
        printf("wolfCrypt self-test passed.\n");
        #endif /* WOLFSSL_BSDKM_VERBOSE_DEBUG */
    }
    #endif /* NO_CRYPT_TEST */

    /**
     * todo: register wolfcrypt algs here with crypto_get_driverid
     * and related.
     * */

    if (ret == 0) {
        printf("info: libwolfssl loaded\n");
    }

    return ret;
}

static int wolfkmod_unload(void)
{
    int ret = 0;

    ret = wolfkmod_cleanup();

    /**
     * todo: unregister wolfcrypt algs here with crypto_unregister_all
     * and related.
     * */

    if (ret == 0) {
        printf("info: libwolfssl unloaded\n");
    }

    return ret;
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

    return ret;
}
#endif /* !BSDKM_CRYPTO_REGISTER */

#if defined(BSDKM_CRYPTO_REGISTER)
/* libwolf device driver software context. */
struct libwolf_softc {
    int32_t driver_id;
};

struct libwolf_session {
    int32_t driver_id;
    int32_t todo_placeholder;
};

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

    softc = device_get_softc(dev);

    softc->driver_id = crypto_get_driverid(dev, sizeof(struct libwolf_session),
                                           flags);
    if (softc->driver_id < 0) {
        printf("error: libwolf: crypto_get_driverid failed: %d\n",
               softc->driver_id);
        return (ENXIO);
    }

    return (0);
}

static int libwolf_detach(device_t dev)
{
    struct libwolf_softc * softc = NULL;

    softc = device_get_softc(dev);
    if (softc->driver_id > 0) {
        crypto_unregister_all(softc->driver_id);
        softc->driver_id = 0;
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

static int libwolf_newsession(device_t dev, crypto_session_t cses,
                              const struct crypto_session_params *csp)
{
    struct libwolf_session * session = NULL;
    int error = 0;

    session = crypto_get_driver_session(cses);
    (void)dev;
    (void)cses;
    (void)csp;
    (void)session;

    return error;
}

static int libwolf_process(device_t dev, struct cryptop *crp, int hint)
{
    const struct crypto_session_params *csp;
    struct libwolf_session * session;
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
