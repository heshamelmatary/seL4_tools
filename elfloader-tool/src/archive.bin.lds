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
OUTPUT_ARCH( "riscv" )
OUTPUT_FORMAT("elf64-littleriscv")
*/

OUTPUT_FORMAT("elf64-littleriscv", "elf64-littleriscv", "elf64-littleriscv")
OUTPUT_ARCH(riscv)


SECTIONS
{
    . = ALIGN(8);
    .archive_ar :
    {
        *(.data)
    }
}
