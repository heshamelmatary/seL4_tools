#include "configstring.h"
#include "encoding.h"
#include "mtrap.h"
#include "atomic.h"
#include <stdio.h>

extern uintptr_t first_free_paddr;
extern uintptr_t mem_size;
extern uintptr_t num_harts;
extern volatile uint64_t* mtime;
extern volatile uint32_t* plic_priorities;

static void query_mem(const char* config_string)
{
  //query_result res = query_config_string(config_string, "ram{0{addr");
  //assert(res.start);
  //uintptr_t base = get_uint(res);
  uintptr_t base = DRAM_BASE;
  assert(base == DRAM_BASE);
  //res = query_config_string(config_string, "ram{0{size");
  //mem_size = get_uint(res);
  mem_size = 4*1024*1024*1024;
}

static void query_rtc(const char* config_string)
{
  //query_result res = query_config_string(config_string, "rtc{addr");
  //assert(res.start);
  //mtime = (void*)(uintptr_t)get_uint(res);
  mtime = 0;
}

static void query_plic(const char* config_string)
{
  //query_result res = query_config_string(config_string, "plic{priority");
  //if (!res.start)
  //  return;
  //plic_priorities = (uint32_t*)(uintptr_t)get_uint(res);

  //res = query_config_string(config_string, "plic{ndevs");
  //if (!res.start)
  //  return;
  //plic_ndevs = get_uint(res);
}

static void query_hart_plic(const char* config_string, hls_t* hls, int core, int hart)
{
  char buf[32];
  snprintf(buf, sizeof buf, "core{%d{%d{plic{m{ie", core, hart);
  query_result res = query_config_string(config_string, buf);
  if (res.start)
    hls->plic_m_ie = (void*)(uintptr_t)get_uint(res);

  snprintf(buf, sizeof buf, "core{%d{%d{plic{m{thresh", core, hart);
  res = query_config_string(config_string, buf);
  if (res.start)
    hls->plic_m_thresh = (void*)(uintptr_t)get_uint(res);

  snprintf(buf, sizeof buf, "core{%d{%d{plic{s{ie", core, hart);
  res = query_config_string(config_string, buf);
  if (res.start)
    hls->plic_s_ie = (void*)(uintptr_t)get_uint(res);

  snprintf(buf, sizeof buf, "core{%d{%d{plic{s{thresh", core, hart);
  res = query_config_string(config_string, buf);
  if (res.start)
    hls->plic_s_thresh = (void*)(uintptr_t)get_uint(res);
}

static void query_harts(const char* config_string)
{
    /*
  for (int core = 0, hart; ; core++) {
    for (hart = 0; ; hart++) {
      char buf[32];
      snprintf(buf, sizeof buf, "core{%d{%d{addr", core, hart);
      query_result res = query_config_string(config_string, buf);
      if (!res.start)
        break;
      csr_t* base = (csr_t*)get_uint(res);
      uintptr_t hart_id = base[CSR_MHARTID];
      hls_init(hart_id, base);
      num_harts++;
      assert(hart_id == num_harts-1);
    }
    if (!hart)
      break;
  }
  assert(num_harts);
  assert(num_harts <= MAX_HARTS);
  */
      /* FIXME: just use one core for now */
      num_harts = 1;
}

void parse_config_string()
{                                                
  //uint32_t addr = *(uint32_t*)CONFIG_STRING_ADDR;
  //const char* s = (const char*)(uintptr_t)addr;  

  //query_mem(s);
  mem_size = 4*1024*1024*1024;
  mtime = 0;
  num_harts = 1;
  //query_plic(s);
  //query_rtc(s);
  //query_harts(s);
}
