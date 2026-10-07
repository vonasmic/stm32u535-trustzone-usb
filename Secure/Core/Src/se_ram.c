/**
 * @file    se_ram.c
 * @brief   SRAM4 NV page and DER scratch; creds workspace on the arena
 *
 * The NV flash image and the shared DER scratch live in SRAM4. The arena
 * workspace is only the creds page (8 KB, or 8 KB plus a spare DER).
 */
#include "se_ram.h"
#include "se_nv.h"
#include "se_creds.h"
#include "se_tropic_port.h"
#include <string.h>
#include <wolfssl/wolfcrypt/memory.h>

_Static_assert(SE_DER_SCRATCH_SIZE == SE_NV_SK_MAX, "DER scratch must hold the device SK");
_Static_assert(SE_DER_SCRATCH_SIZE >= SE_CREDS_DER_MAX, "DER scratch must hold a cert");

static uint8_t s_der_scratch[SE_DER_SCRATCH_SIZE] SE_SRAM4_BSS;
static uint8_t s_nv_page[SE_NV_PAGE_SIZE] SE_SRAM4_BSS;
static uint8_t s_nv_page_held;

void se_sram4_bss_init(void)
{
    extern uint8_t _ssram4;
    extern uint8_t _esram4;
    uintptr_t start = (uintptr_t)&_ssram4;
    uintptr_t end = (uintptr_t)&_esram4;

    if (end > start) {
        (void)memset((void *)start, 0, (size_t)(end - start));
    }
}

volatile uint32_t se_heap_used;
volatile uint32_t se_heap_free;

static void *s_ws;
static size_t s_ws_n;

uint8_t *se_der_scratch(void)
{
    return s_der_scratch;
}

uint8_t *se_nv_page_acquire(void)
{
    if (s_nv_page_held != 0U) {
        return NULL;
    }
    s_nv_page_held = 1U;
    return s_nv_page;
}

void se_nv_page_release(void)
{
    if (s_nv_page_held == 0U) {
        return;
    }
    wc_ForceZero(s_nv_page, sizeof(s_nv_page));
    s_nv_page_held = 0U;
}

void se_ram_sample(void)
{
#if defined(USE_HAL_DRIVER)
    extern uint8_t _end;
    extern uint8_t _estack;
    extern uint32_t _Min_Stack_Size;
    extern void *_sbrk(ptrdiff_t incr);
    uint8_t *top = (uint8_t *)_sbrk(0);
    uintptr_t lim = (uintptr_t)&_estack - (uintptr_t)&_Min_Stack_Size;

    se_heap_used = (uint32_t)(top - &_end);
    se_heap_free = (lim > (uintptr_t)top) ? (uint32_t)(lim - (uintptr_t)top) : 0U;
#endif
    se_mem_measure();
}

void *se_workspace_acquire(size_t n)
{
    if ((s_ws != NULL) || (n == 0U)) {
        return NULL;
    }
    s_ws = se_mem_alloc(n, 0);
    if (s_ws != NULL) {
        s_ws_n = n;
    }
    return s_ws;
}

void se_workspace_release(void)
{
    if (s_ws == NULL) {
        return;
    }
    wc_ForceZero(s_ws, s_ws_n);
    se_mem_free(s_ws);
    s_ws = NULL;
    s_ws_n = 0U;
}
