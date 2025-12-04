#if !defined(WC_SKIP_INCLUDED_C_FILES) && defined(BSDKM_CRYPTO_REGISTER)
#include <wolfssl/wolfcrypt/aes.h>

/*
 * cryptodev framework always uses a callback, even when sync.
 */
static int
wolfkdriv_test_crp_callback(struct cryptop * crp)
{
    (void)crp;
    return (0);
}

static int wolfkdriv_test_aes(device_t dev, int crid)
{
    crypto_session_t session = NULL;
    struct crypto_session_params csp;
    struct cryptop * crp = NULL;
    int    error = 0;
    byte msg[] = {
        0x6e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
        0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20,
        0x66,0x6f,0x72,0x20,0x61,0x6c,0x6c,0x20
    };
    const byte verify[] =
    {
        0x95,0x94,0x92,0x57,0x5f,0x42,0x81,0x53,
        0x2c,0xcc,0x9d,0x46,0x77,0xa2,0x33,0xcb
    };
    /* padded to 16-bytes */
    const byte key[] = "0123456789abcdef   ";
    /* padded to 16-bytes */
    const byte iv[]  = "1234567890abcdef   ";

    memset(&csp, 0, sizeof(csp));

    /* cbc */
    csp.csp_cipher_alg = CRYPTO_AES_CBC;
    csp.csp_mode = CSP_MODE_CIPHER;
    csp.csp_ivlen = AES_GCM_IV_LEN;
    csp.csp_cipher_key = key;
    csp.csp_cipher_klen = sizeof(key);
    error = crypto_newsession(&session, &csp, crid);
    if (error || session == NULL) {
        goto test_aes_out;
    }

    crp = crypto_getreq(session, M_WAITOK);
    if (crp == NULL) {
        device_printf(dev, "error: test_aes: crypto_getreq failed\n");
        goto test_aes_out;
    }

    crp->crp_callback = wolfkdriv_test_crp_callback;
    crp->crp_op = CRYPTO_OP_ENCRYPT;
    crp->crp_flags = CRYPTO_F_IV_SEPARATE;

    memcpy(crp->crp_iv, iv, 16);
    crypto_use_buf(crp, msg, sizeof(msg));

    error = crypto_dispatch(crp);

    (void)verify;
test_aes_out:
    #if defined(WOLFSSL_BSDKM_VERBOSE_DEBUG)
    device_printf(dev, "info: test_aes: error=%d, session=%p, crp=%p\n",
                  error, (void *)session, (void*)crp);
    #endif /* WOLFSSL_BSDKM_VERBOSE_DEBUG */

    if (crp != NULL) {
        crypto_freereq(crp);
        crp = NULL;
    }

    if (session != NULL) {
        crypto_freesession(session);
        session = NULL;
    }

    return (error);
}
#endif /* !WC_SKIP_INCLUDED_C_FILES && BSDKM_CRYPTO_REGISTER */
