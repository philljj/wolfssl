#if !defined(WC_SKIP_INCLUDED_C_FILES) && defined(BSDKM_CRYPTO_REGISTER)
#include <wolfssl/wolfcrypt/aes.h>

static int wolfkdriv_test_aes(int crid)
{
    crypto_session_t session = NULL;
    struct crypto_session_params csp;
    int error = 0;
    uint8_t key[16] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                       0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};

    memset(&csp, 0, sizeof(csp));

    /* gcm */
    csp.csp_cipher_alg = CRYPTO_AES_NIST_GCM_16;
    csp.csp_mode = CSP_MODE_AEAD;
    csp.csp_ivlen = AES_GCM_IV_LEN;
    csp.csp_cipher_key = key;
    csp.csp_cipher_klen = sizeof(key);

    error = crypto_newsession(&session, &csp, crid);

    if (session != NULL) {
        crypto_freesession(session);
        session = NULL;
    }

    return (error);
}
#endif /* !WC_SKIP_INCLUDED_C_FILES && BSDKM_CRYPTO_REGISTER */
