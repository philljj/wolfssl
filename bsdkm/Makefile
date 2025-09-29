# declare module name and sources
KMOD=wolfkmod
SRCS=wolfkmod.c
WOLFSSL_DIR=../

CFLAGS+= -I/usr/include/sys
CFLAGS+=-I${WOLFSSL_DIR} -DHAVE_CONFIG_H $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS)

# gimmicky test, replace with real src obj pattern
OBJS+= \
    ${WOLFSSL_DIR}/wolfcrypt/src/sha256.o \
    ${WOLFSSL_DIR}/wolfcrypt/src/logging.o \
    ${WOLFSSL_DIR}/wolfcrypt/src/memory.o

# point to live kernel kmod dot mk
.include "/usr/src/sys/conf/kmod.mk"

# suppress wolfcrypt/src/misc.c drops const qualifier
CFLAGS+= -Wno-cast-qual
CFLAGS+= -Wno-shorten-64-to-32
CFLAGS+= -Wno-error=cast-qual
CFLAGS+= -DLIBWOLFSSL_GLOBAL_EXTRA_CFLAGS="\" $(KERNEL_EXTRA_CFLAGS)\""
