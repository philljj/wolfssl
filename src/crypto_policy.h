/* crypto_policy.h
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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
#ifndef WOLFSSL_CRYPTO_POLICY_GRANULAR_H
#define WOLFSSL_CRYPTO_POLICY_GRANULAR_H

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_SYS_CRYPTO_POLICY)

#include <wolfssl/internal.h>
#include <wolfssl/ssl.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif


#define WOLF_CP_OK                  0
#define WOLF_CP_ERR_SYNTAX         -1
#define WOLF_CP_ERR_NOT_ALLOWLIST  -2
#define WOLF_CP_ERR_OVERFLOW       -3
#define WOLF_CP_ERR_EMPTY          -4


/* Header sniff: 1 if buffer looks like a granular allowlist file,
 *               0 if legacy single-line @SECLEVEL= format. */
WOLFSSL_LOCAL int wolfSSL_crypto_policy_is_granular(const char *buf);

/* Parse a granular allowlist buffer into a WolfGranularPolicy. */
WOLFSSL_LOCAL int wolfSSL_crypto_policy_parse_granular(
    const char *buf, WolfGranularPolicy *out, char *err, size_t errlen);

/* Derive a wolfSSL-style cipher list string from the parsed policy. */
WOLFSSL_LOCAL int wolfSSL_crypto_policy_derive_cipher_list(
    const WolfGranularPolicy *p, char *out, size_t outlen);

/* Derive a wolfSSL sigalgs list string from the parsed policy. */
WOLFSSL_LOCAL int wolfSSL_crypto_policy_derive_sigalgs_list(
    const WolfGranularPolicy *p, char *out, size_t outlen);

/* Lowest enabled version inside the requested protocol family.
 * is_dtls != 0 considers only DTLS tokens, is_dtls == 0 considers
 * only TLS tokens. Returns -1 if no token of that family is enabled. */
WOLFSSL_LOCAL int wolfSSL_crypto_policy_min_version(
    const WolfGranularPolicy *p, int is_dtls);

/* Apply the parsed policy to a CTX: drive SetMinVersion,
 * set_cipher_list, UseSupportedCurve, set1_sigalgs_list and
 * SetMin{Rsa,Dh,Ecc}Key_Sz. */
WOLFSSL_LOCAL int wolfSSL_crypto_policy_apply_granular(
    WOLFSSL_CTX *ctx, const WolfGranularPolicy *p);

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_SYS_CRYPTO_POLICY */

#endif /* WOLFSSL_CRYPTO_POLICY_GRANULAR_H */
