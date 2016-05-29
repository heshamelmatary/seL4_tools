#include <autoconf.h>

#include "stdint.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "elf/elf.h"
#include "elfloader.h"
#include <platform.h>

#include <cpio/cpio.h>

#define MIN(a, b) (((a)<(b))?(a):(b))

/*************************** MMU ************************************/

#define MSTATUS_IE          0x00000001
#define MSTATUS_PRV         0x00000006
#define MSTATUS_IE1         0x00000008
#define MSTATUS_PRV1        0x00000030
#define MSTATUS_IE2         0x00000040
#define MSTATUS_PRV2        0x00000180
#define MSTATUS_IE3         0x00000200
#define MSTATUS_PRV3        0x00000C00
#define MSTATUS_FS          0x00003000
#define MSTATUS_XS          0x0000C000
#define MSTATUS_MPRV        0x00010000
#define MSTATUS_VM          0x003E0000
#define MSTATUS32_SD        0x80000000
#define MSTATUS64_SD        0x8000000000000000

#define PRV_U 0 
#define PRV_S 1 
#define PRV_H 2 
#define PRV_M 3 

#define VM_MBARE 0
#define VM_MBB   1
#define VM_MBBID 2
#define VM_SV32  8
#define VM_SV39  9
#define VM_SV48  10

#define PTE_TYPE_TABLE 0x00
#define PTE_TYPE_TABLE_GLOBAL 0x02
#define PTE_TYPE_URX_SR 0x04
#define PTE_TYPE_URWX_SRW 0x06
#define PTE_TYPE_UR_SR 0x08
#define PTE_TYPE_URW_SRW 0x0A
#define PTE_TYPE_URX_SRX 0x0C
#define PTE_TYPE_URWX_SRWX 0x0E
#define PTE_TYPE_SR 0x10
#define PTE_TYPE_SRW 0x12
#define PTE_TYPE_SRX 0x14
#define PTE_TYPE_SRWX 0x16
#define PTE_TYPE_SR_GLOBAL 0x18
#define PTE_TYPE_SRW_GLOBAL 0x1A
#define PTE_TYPE_SRX_GLOBAL 0x1C
#define PTE_TYPE_SRWX_GLOBAL 0x1E

#define RISCV_PGSHIFT 12
#define RISCV_PGSIZE (1 << RISCV_PGSHIFT)

// page table entry (PTE) fields
#define PTE_V     0x001 // Valid
#define PTE_TYPE  0x01E // Type 
#define PTE_R     0x020 // Referenced
#define PTE_D     0x040 // Dirty
#define PTE_SOFT  0x380 // Reserved for Software

#define PTE_PPN_SHIFT 10
#define PTE_PPN1_SHIFT 20

#define PTE64_PPN2_SHIFT 28
#define PTE64_PPN1_SHIFT 19
#define PTE64_PPN0_SHIFT 10 

#ifndef CONFIG_ROCKET_CHIP
#define PTES_PER_PT (RISCV_PGSIZE/sizeof(long))
#else
#define PTES_PER_PT (RISCV_PGSIZE/8)
#endif

/* Virtual address to index conforming sv32 PTE format */ 
#define VIRT1_TO_IDX(addr) ((addr) >> 22)
#define VIRT0_TO_IDX(addr) (((addr) >> 12)

#define SV39_VIRT_TO_VPN2(addr) ((addr) >> 30)
#define SV39_VIRT_TO_VPN1(addr) ((addr) >> 21)
#define SV39_VIRT_TO_VPN0(addr) ((addr) >> 12)

#define PTE_CREATE(PPN, TYPE) (((PPN) << PTE_PPN_SHIFT) | (TYPE) | PTE_V)
#define PTE64_CREATE(PPN, TYPE) (uint64_t) (((uint32_t)PPN) | (TYPE) | PTE_V)
#define PTE64_PT_CREATE(PT_BASE) \
  (((uint32_t)(PT_BASE) / RISCV_PGSIZE) << 10 | PTE_TYPE_TABLE | PTE_V)

#define write_csr(reg, val) \
  asm volatile ("csrw " #reg ", %0" :: "r"(val))

#define swap_csr(reg, val) ({ long __tmp; asm volatile ("csrrw %0, " #reg ", %1" : "=r"(__tmp) : "r"(val)); \
  __tmp; })

#define set_csr(reg, bit) ({ unsigned long __tmp; \
  if (__builtin_constant_p(bit) && (bit) < 32) \
  asm volatile ("csrrs %0, " #reg ", %1" : "=r"(__tmp) : "i"(bit)); \
  else \
  asm volatile ("csrrs %0, " #reg ", %1" : "=r"(__tmp) : "r"(bit)); \
  __tmp; })

#define clear_csr(reg, bit) ({ unsigned long __tmp; \
  if (__builtin_constant_p(bit) && (bit) < 32) \
  asm volatile ("csrrc %0, " #reg ", %1" : "=r"(__tmp) : "i"(bit)); \
  else \
    asm volatile ("csrrc %0, " #reg ", %1" : "=r"(__tmp) : "r"(bit)); \
  __tmp; })


#ifndef CONFIG_ROCKET_CHIP
uint32_t l1pt[PTES_PER_PT] __attribute__((aligned(4096)));
uint32_t l2pt[PTES_PER_PT] __attribute__((aligned(4096)));
#else
uint64_t l1pt[PTES_PER_PT] __attribute__((aligned(4096)));
uint64_t l2pt_elfloader[PTES_PER_PT] __attribute__((aligned(4096)));
uint64_t l2pt_kernel[PTES_PER_PT] __attribute__((aligned(4096)));
#endif
void
map_kernel_window(struct image_info *kernel_info)
{
    
    
    uint32_t i;
    paddr_t  phys;
    #ifdef CONFIG_ROCKET_CHIP
    phys = SV39_VIRT_TO_VPN1(kernel_info->phys_region_start) & 0x1FF;
    #else
    uint32_t idx; 
    phys = VIRT1_TO_IDX(kernel_info->phys_region_start);
    idx = VIRT1_TO_IDX(0x40000000);
    #endif
    printf("phys = %d \n", phys);
    //printf("kernel_info = 0x%x\n", *kernel_info);

  //printf("idx = %d \n", idx);

/* This is a hack to run 32-bit code on SV39/RV64 machine. It maps the first 16
 * MiB for elfloader (1:1) mapping, and 256 MiB for kernel at 0xF0000000 at 
 * 2 MiB granularity.
 */
#ifdef CONFIG_ROCKET_CHIP
  /* Only 4 GiB need to be mapped, the first (first-level) PTE would refer to 
   * a second level page table to 1:1 map the elfloader (16Mib)
   */ 
   l1pt[0] =  PTE64_PT_CREATE((uint32_t)(&l2pt_elfloader));
  
   for(i = 0; i < 8; i++)
     l2pt_elfloader[i] = PTE64_CREATE((uint32_t)(i << PTE64_PPN1_SHIFT), PTE_TYPE_SRWX);
  
   /* 256 MiB kernel mapping (128 PTE * 2MiB per entry) */
   l1pt[1] =  PTE64_PT_CREATE(&l2pt_kernel);
   for(i = 0; i < 128; i++, phys++)
     /* The first two bits are always 0b11 since the MSB is 0xF */
     l2pt_kernel[i] = PTE64_CREATE(phys << PTE64_PPN1_SHIFT, PTE_TYPE_SRWX);
  
#else
  for(i = 0; i < idx ; i++)
  {
    l1pt[i] =  PTE_CREATE(i << 10, PTE_TYPE_SRWX);
  }

  /*  4 MiB Mega Pages */
  for(i = 0; idx < PTES_PER_PT ; idx++, phys++)
  {
    l1pt[idx] = PTE_CREATE(phys << 10, PTE_TYPE_SRWX);            
  }
#endif

  write_csr(sptbr, l1pt);

  set_csr(mstatus, MSTATUS_IE1);
  set_csr(mstatus, MSTATUS_PRV1);
  clear_csr(mstatus, MSTATUS_VM);
  
#ifndef CONFIG_ROCKET_CHIP
  set_csr(mstatus, (long)VM_SV32 << __builtin_ctzl(MSTATUS_VM));
#else
  set_csr(mstatus, (long)VM_SV39 << __builtin_ctzl(MSTATUS_VM));
#endif
  /* Set to supervisor mode */
  clear_csr(mstatus, (long) PRV_H << __builtin_ctzl(MSTATUS_PRV));
}

/**********************************MMU ******************************************/
/* Determine if two intervals overlap. */
static int
regions_overlap(uint32_t startA, uint32_t endA,
                uint32_t startB, uint32_t endB)
{
    if (endA < startB) {
        return 0;
    }
    if (endB < startA) {
        return 0;
    }
    return 1;
}

/*
 * Ensure that we are able to use the given physical memory range.
 *
 * We abort if the destination physical range overlaps us, or if it
 * goes outside the bounds of memory.
 */
static void ensure_phys_range_valid(paddr_t paddr_min, paddr_t paddr_max)
{
    /* Ensure that the kernel physical load address doesn't overwrite us. */
    if (regions_overlap(paddr_min, paddr_max - 1,
                        (uint32_t)_start, (uint32_t)_end - 1)) {
        printf("Kernel load address would overlap ELF-loader!\n");
        abort();
    }
}

/*
 * Unpack an ELF file to the given physical address.
 */
static void unpack_elf_to_paddr(void *elf, paddr_t dest_paddr)
{
    uint64_t min_vaddr, max_vaddr;
    uint32_t image_size;
    uint32_t phys_virt_offset;
    int i;

    /* Get size of the image. */
    elf_getMemoryBounds(elf, 0, &min_vaddr, &max_vaddr);
    image_size = (uint32_t)(max_vaddr - min_vaddr);
    phys_virt_offset = (uint32_t)dest_paddr - (uint32_t)min_vaddr;

    /* Zero out all memory in the region, as the ELF file may be sparse. */
    memset((char *)dest_paddr, 0, image_size);

    /* Load each segment in the ELF file. */
    for (i = 0; i < elf_getNumProgramHeaders(elf); i++) {
        vaddr_t dest_vaddr;
        uint32_t data_size, data_offset;

        /* Skip segments that are not marked as being loadable. */
        if (elf32_getProgramHeaderType(elf, i) != PT_LOAD) {
            continue;
        }

        /* Parse size/length headers. */
        dest_vaddr = elf_getProgramHeaderVaddr(elf, i);
        data_size = elf_getProgramHeaderFileSize(elf, i);
        data_offset = elf_getProgramHeaderOffset(elf, i);

        /* Load data into memory. */
        memcpy((char *)dest_vaddr + phys_virt_offset,
               (char *)elf + data_offset, data_size);
    }
}

/*
 * Load an ELF file into physical memory at the given physical address.
 *
 * Return the byte past the last byte of the physical address used.
 */
static paddr_t load_elf(const char *name, void *elf,
                        paddr_t dest_paddr, struct image_info *info)
{
    uint64_t min_vaddr, max_vaddr;
    uint32_t image_size;

    /* Fetch image info. */
    elf_getMemoryBounds(elf, 0, &min_vaddr, &max_vaddr);
    max_vaddr = ROUND_UP(max_vaddr, PAGE_BITS);
    image_size = (uint32_t)(max_vaddr - min_vaddr);

    /* Ensure our starting physical address is aligned. */
    if (!IS_ALIGNED(dest_paddr, PAGE_BITS)) {
        printf("dest address = 0x%x \n", dest_paddr); 
        printf("Attempting to load ELF at unaligned physical address!\n");
        abort();
    }

    /* Ensure that the ELF file itself is 4-byte aligned in memory, so that
     * libelf can perform word accesses on it. */
    if (!IS_ALIGNED(dest_paddr, 2)) {
        printf("Input ELF file not 4-byte aligned in memory!\n");
        abort();
    }

    /* Print diagnostics. */
    printf("ELF-loading image '%s'\n", name);
    printf("  paddr=[%x..%x]\n", dest_paddr, dest_paddr + image_size - 1);
    printf("vaddr = 0x%x\n", (uint32_t) min_vaddr);
    printf("  vaddr=[%x..%x]\n", (uint32_t)min_vaddr, (uint32_t)max_vaddr - 1);
    printf("  virt_entry=%x\n", (uint32_t)elf_getEntryPoint(elf));

    /* Ensure the ELF file is valid. */
    if (elf_checkFile(elf) != 0) {
        printf("Attempting to load invalid ELF file '%s'.\n", name);
        abort();
    }

    /* Ensure sane alignment of the image. */
    if (!IS_ALIGNED(min_vaddr, PAGE_BITS)) {
        printf("Start of image '%s' is not 4K-aligned!\n", name);
        abort();
    }

    /* Ensure that we region we want to write to is sane. */
    ensure_phys_range_valid(dest_paddr, dest_paddr + image_size);

    /* Copy the data. */
    unpack_elf_to_paddr(elf, dest_paddr);

    /* Record information about the placement of the image. */
    info->phys_region_start = dest_paddr;
    info->phys_region_end = dest_paddr + image_size;
    info->virt_region_start = (vaddr_t)min_vaddr;
    info->virt_region_end = (vaddr_t)max_vaddr;
    info->virt_entry = (vaddr_t)elf_getEntryPoint(elf);
    printf("info->virt_entry = 0x%x\n", info->virt_entry);
    info->phys_virt_offset = (uint32_t)dest_paddr - (uint32_t)min_vaddr;

    /* Return address of next free physical frame. */
    return ROUND_UP(dest_paddr + image_size, PAGE_BITS);
}

typedef void (*init_kernel_t)(paddr_t ui_p_reg_start,
                              paddr_t ui_p_reg_end, int32_t pv_offset, vaddr_t v_entry);

void load_images(struct image_info *kernel_info, struct image_info *user_info,
                 int max_user_images, int *num_images)
{
    int i;
    uint64_t kernel_phys_start, kernel_phys_end;
    paddr_t next_phys_addr;
    const char *elf_filename;
    unsigned long unused;

    /* Load kernel. */
    void *kernel_elf = cpio_get_file(_archive_start, "kernel.elf", &unused);
    if (kernel_elf == NULL) {
        printf("No kernel image present in archive!\n");
        abort();
    }
    if (elf_checkFile(kernel_elf)) {
        printf("Kernel image not a valid ELF file!\n");
        abort();
    }
    elf_getMemoryBounds(kernel_elf, 1,
                        &kernel_phys_start, &kernel_phys_end);

    kernel_phys_end = 0x1000000 + kernel_phys_end - kernel_phys_start;
    kernel_phys_start = 0x1000000;
    
    next_phys_addr = load_elf("kernel", kernel_elf,
                              (paddr_t)kernel_phys_start, kernel_info);

    /*
     * Load userspace images.
     *
     * We assume (and check) that the kernel is the first file in the archive,
     * and then load the (n+1)'th file in the archive onto the (n)'th CPU.
     */
    (void)cpio_get_entry(_archive_start, 0, &elf_filename, &unused);
    if (strcmp(elf_filename, "kernel.elf") != 0) {
        printf("Kernel image not first image in archive.\n");
        abort();
    }
    *num_images = 0;
    for (i = 0; i < max_user_images; i++) {
        /* Fetch info about the next ELF file in the archive. */
        void *user_elf = cpio_get_entry(_archive_start, i + 1,
                                        &elf_filename, &unused);
        if (user_elf == NULL) {
            break;
        }

        /* Load the file into memory. */
        next_phys_addr = load_elf(elf_filename, user_elf,
                                  next_phys_addr, &user_info[*num_images]);
        *num_images = i + 1;
    }
}

static struct image_info kernel_info;
static struct image_info user_info;

void main(void)
{


    int num_apps = 0;

      /* Print welcome message. */
    printf("\nELF-loader started on ");

    platform_init();

    printf("  paddr=[%p..%p]\n", _start, _end - 1); 

    /* Unpack ELF images into memory. */
    load_images(&kernel_info, &user_info, 1, &num_apps);
    if (num_apps != 1) {
        printf("No user images loaded!\n");
        abort();
    }

    printf("1: Kernel entry point is 0x%x\n", kernel_info.virt_entry);
    map_kernel_window(&kernel_info);

    printf("Jumping to kernel-image entry point...\n\n");
    /* Uncomment the following line to get a weird behavior! */
    //printf("2: Kernel entry point is 0x%x\n", kernel_info.virt_entry);
    ((init_kernel_t)kernel_info.virt_entry)(user_info.phys_region_start,
                                            user_info.phys_region_end, user_info.phys_virt_offset,
                                            user_info.virt_entry);

  /* We should never get here. */
    printf("Kernel returned back to the elf-loader.\n");
}
