/*
 * Copyright 2014, NICTA
 *
 * This software may be distributed and modified according to the terms of
 * the GNU General Public License version 2. Note that NO WARRANTY is provided.
 * See "LICENSE_GPLv2.txt" for details.
 *
 * @TAG(NICTA_GPL)
 */

#ifndef _STDINT_H
#define _STDINT_H 1

typedef signed char int8_t;
typedef short int16_t;
typedef int int32_t;
typedef long long int64_t;

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;

typedef unsigned long uintptr_t;
typedef long  intptr_t;
typedef unsigned long size_t;

#define UINT64_MAX (18446744073709551615ULL)

#if __riscv_xlen == 32
#define __PTR_SIZE 32
#else
#define __PTR_SIZE 64
#endif
#endif
