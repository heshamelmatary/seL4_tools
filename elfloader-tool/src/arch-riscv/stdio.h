/*
 * Copyright 2014, NICTA
 *
 * This software may be distributed and modified according to the terms of
 * the GNU General Public License version 2. Note that NO WARRANTY is provided.
 * See "LICENSE_GPLv2.txt" for details.
 *
 * @TAG(NICTA_GPL)
 */

#ifndef _STDIO_H_
#define _STDIO_H_

#include "stdint.h"

# ifndef __ssize_t_defined
typedef int64_t __ssize_t; 
# define __ssize_t_defined
#endif
typedef int64_t ssize_t; 

#define NULL ((void *)0)
#define FILE void

/* Architecture-specific putchar implementation. */
int __fputc(int c, FILE *data);

int printf(const char *format, ...);
int sprintf(char *buff, const char *format, ...);

#endif
