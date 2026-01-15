/* x86_vecreg.c -- logic to save and restore vector registers
 * on amd64 in FreeBSD kernel.
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

/* included by bsdkm/wolfkmod.c */
#ifndef WC_SKIP_INCLUDED_C_FILES

#include <sys/smp.h>

struct wolfkmod_fpu_state_t {
    u_int cpuid;
    u_int nest;
};

typedef struct wolfkmod_fpu_state_t wolfkmod_fpu_state_t;

wolfkmod_fpu_state_t * fpu_states = NULL;

int wolfkmod_vecreg_init(void)
{
    fpu_states = malloc(mp_ncpus * sizeof(wolfkmod_fpu_state_t),
                        M_WOLFSSL, M_WAITOK | M_ZERO);
    if (fpu_states == NULL) {
        return (ENOMEM);
    }

    return (0);
}

int wolfkmod_save_vecreg(int flags_unused)
{
    (void)flags_unused;

    if (is_fpu_kern_thread(0) || curthread->td_pcb->pcb_flags & PCB_KERNFPU) {
        fpu_states[PCPU_GET(cpuid)].nest++;
    }
    else {
        wolfkmod_fpu_kern_enter();
        if (fpu_states[PCPU_GET(cpuid)].nest != 0) {
            printf("error: wolfkmod_fpu_kern_enter() with nest: %d\n",
                   fpu_states[PCPU_GET(cpuid)].nest);
            return (EINVAL);
        }

        fpu_states[PCPU_GET(cpuid)].nest++;
    }

    return (0);
}

void wolfkmod_restore_vecreg(void)
{
    if (is_fpu_kern_thread(0) || curthread->td_pcb->pcb_flags & PCB_KERNFPU) {
        if (fpu_states[PCPU_GET(cpuid)].nest > 0) {
            fpu_states[PCPU_GET(cpuid)].nest--;
        }

        if (fpu_states[PCPU_GET(cpuid)].nest == 0) {
            wolfkmod_fpu_kern_leave();
        }
    }

    return;
}

#endif /* !WC_SKIP_INCLUDED_C_FILES */
