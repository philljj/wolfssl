/* bsdkm_wc_port.h
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

/* included by wolfssl/wolfcrypt/wc_port.h */

#ifndef BSDKM_WC_PORT_H
#define BSDKM_WC_PORT_H

#include <sys/types.h>
#include <sys/malloc.h>
#include <sys/libkern.h>
#include <sys/systm.h>

#define XATOI(s) ({                                         \
      char * endptr = NULL;                                 \
      long   _xatoi_ret = strtol(s, &endptr, 10);           \
      if ((s) == endptr || endptr != '\0') {                \
        _xatoi_ret = 0;                                     \
      }                                                     \
      (int)_xatoi_ret;                                      \
    })

#if !defined(XMALLOC_OVERRIDE)
    #error bsdkm requires XMALLOC_OVERRIDE
#endif /* !XMALLOC_OVERRIDE */

/* This is incorrect placeholder. Likely need:
 *   - MALLOC_DEFINE(M_WOLFSSL, "wolfssl", "wolfSSL kernel memory");
       in the main wolfkmod source file.
 *   - Need to use contigmalloc or malloc from sys/malloc.h
 *   - Need extern struct malloc_type M_WOLFSSL; here or elsewhere.
 *   - */
        /* placeholder, fix later. */
#define XMALLOC(s, h, t)     ({(void)(h); (void)(t); malloc(s, NULL, 0);})
#ifdef WOLFSSL_XFREE_NO_NULLNESS_CHECK
    #define XFREE(p, h, t)       ({(void)(h); (void)(t); free(p);})
#else
    #define XFREE(p, h, t)       ({void* _xp; (void)(h); (void)(t); _xp = (p); if(_xp) free(_xp);})
#endif

#ifndef CHAR_BIT
    #include <sys/limits.h>
#endif /* !CHAR_BIT*/

#endif /* BSDKM_WC_PORT_H */
