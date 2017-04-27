/*
 * Copyright 2014, NICTA
 *
 * This software may be distributed and modified according to the terms of
 * the GNU General Public License version 2. Note that NO WARRANTY is provided.
 * See "LICENSE_GPLv2.txt" for details.
 *
 * @TAG(NICTA_GPL)
 */

/*
 * Platform-specific putchar implementation.
 */

#include "../stdint.h"
#include "../stdio.h"
#include "platform.h"
#include "sbi.h"

int
__fputc(int c, FILE *stream __attribute__((unused)))
{
  sbi_console_putchar(c);
  return 0;
}
