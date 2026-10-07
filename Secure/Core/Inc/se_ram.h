/**
 * @file    se_ram.h
 * @brief   Secure arena allocator, SRAM4 NV page, and debugger watermarks
 *
 * All Secure dynamic memory (wolfSSL via XMALLOC_USER and the app buffers)
 * comes from the fixed arena in se_xmallo.c. Watch:
 *   se_mem_live          bytes held now (block headers included)
 *   se_mem_session_peak  most bytes held during the current TLS session
 *   se_mem_peak          most bytes held since reset
 *   se_mem_idle_live     bytes still held after the last session teardown (must be 0)
 *   se_mem_idle_size/type/caller[4]  first blocks still held at that teardown
 *   se_largest_empty_space  usable bytes in the biggest free block right now
 *   se_mem_free_bytes    sum of free-block sizes (headers included) right now
 *   se_mem_walk_stop     0 if block headers tile the arena, else the bad offset
 *   se_mem_walk_prev_*   block that ends at that offset (caller, size, type)
 *   se_xmallo_fail_n     size of the last request the arena could not place
 *   se_xmallo_fail_live  se_mem_live at that request
 *   se_xmallo_fail_space se_largest_empty_space at that request
 *   se_xmallo_fail_why   1 no hole on the free list, 2 bad pointer,
 *                        3 bad block size, 4 a hole exists but is not linked
 *   se_mem_fail_free_main, se_mem_fail_caller  same hole and the caller then
 * `se_heap_used` / `se_heap_free` still sample the newlib break, which this
 * firmware no longer grows.
 */
#ifndef SE_RAM_H
#define SE_RAM_H

#include <stddef.h>
#include <stdint.h>

extern volatile uint32_t se_heap_used;
extern volatile uint32_t se_heap_free;

/** BSS that does not fit on the TLS stack. Startup does not zero SRAM4. */
#define SE_SRAM4_BSS __attribute__((section(".sram4_bss"), aligned(8)))

/**
 * Short-lived DER scratch in SRAM4 (device SK encoding, TLS cert, client-hash cert).
 * One buffer: each caller finishes and wipes before returning. Do not nest.
 * Same size as SE_NV_SK_MAX. Cert callers pass SE_CREDS_DER_MAX as the cap.
 */
#define SE_DER_SCRATCH_SIZE 4096u

void se_sram4_bss_init(void);
/** SRAM4 DER scratch. Not exclusive; callers must not nest. */
uint8_t *se_der_scratch(void);

/**
 * SRAM4 image of the NV flash page. Not on the arena free list.
 * Exclusive between se_nv commits and the port's dwk / raw page writers.
 */
uint8_t *se_nv_page_acquire(void);
void se_nv_page_release(void);
void se_ram_sample(void);
/** Refresh se_largest_empty_space from the block headers. */
void se_mem_measure(void);

void *se_mem_alloc(size_t n, int type);
void *se_mem_realloc(void *p, size_t n, int type);
void se_mem_free(void *p);

/**
 * Drop every block and return the arena to one free block.
 * Callers must already have freed or abandoned every pointer into the arena.
 */
void se_mem_reset(void);
/** Reset the session peak. Call before the TLS context is created. */
void se_mem_session_begin(void);
/** Record bytes still held. Call after the TLS session is torn down. */
void se_mem_session_end(void);

/** Creds-page workspace on the arena (8 KB, or 8 KB plus a spare DER). */
void *se_workspace_acquire(size_t n);
void se_workspace_release(void);

#endif
