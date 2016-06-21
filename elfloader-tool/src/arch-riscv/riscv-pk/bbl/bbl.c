#include "bbl.h"
#include "mtrap.h"
#include "atomic.h"
#include "vm.h"
#include "bits.h"
#include "config.h"
#include <string.h>
#include <stdio.h>

#include "string.h"
#include "../../elfloader.h"

#include <cpio/cpio.h>

static kernel_elf_info info;

//extern char _sbi_pt_ld[];

void boot_loader()
{
  //extern char _payload_start, _payload_end;
  //load_kernel_elf(&kernel_phys_start, &kernel_phys_end - &kernel_phys_start, &info);
    unsigned long unused;
    uint64_t kernel_phys_start, kernel_phys_end;

    print_logo();
    main();
//    supervisor_vm_init();

    /*
    void *kernel_elf = cpio_get_file(_archive_start, "kernel.elf", &unused);
    if (kernel_elf == NULL) {
//        printf("No kernel image present in archive!\n");
        abort();
    }   
    if (elf_checkFile(kernel_elf)) {
//        printf("Kernel image not a valid ELF file!\n");
        abort();
    }   
    elf_getMemoryBounds(kernel_elf, 1,
                        &kernel_phys_start, &kernel_phys_end);
*/

//#ifdef PK_ENABLE_LOGO
//#endif
  mb();
//  enter_supervisor_mode((void *)info.entry, 0);
}

void boot_other_hart()
{
  while (1)
    ;
  mb();
  //enter_supervisor_mode((void *)info.entry, 0);
}
