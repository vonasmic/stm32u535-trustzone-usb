/**
 * @file    se_xmallo.c
 * @brief   Secure arena allocator for wolfSSL (XMALLOC_USER) and app buffers
 *
 * All Secure dynamic memory comes from one region: SE_MEM_MAIN_LEN bytes in
 * SRAM1/SRAM2 (.bss). newlib malloc is not used. SRAM4 holds the NV page,
 * the shared DER scratch, and other buffers that do not fit on the TLS stack
 * (SE_SRAM4_BSS). It is not a second heap.
 *
 * Placement is best fit (ties go to the lower address). Free keeps the list
 * address-ordered and merges neighbours. When se_mem_live is 0 the region is
 * one free block again, so each TLS session starts from the same state and
 * the same handshake always lands at the same addresses.
 *
 * Every block header records the wolfSSL type and the caller's return
 * address. After a session teardown the first held blocks are copied to
 * se_mem_idle_*; on a failed request the largest free block is copied to
 * se_mem_fail_free_main. se_largest_empty_space is the biggest usable hole
 * found by walking block headers, so it stays valid when the free list does
 * not. Resolve callers with addr2line on the ELF.
 */
#include <stdint.h>
#include <string.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include "se_ram.h"

#ifndef SE_MEM_MAIN_LEN
#define SE_MEM_MAIN_LEN (108u * 1024u)
#endif
#define SE_MEM_IDLE_LOG  4u

#define SE_MEM_ALIGN   8u
#define SE_MEM_HDR     ((uint32_t)sizeof(mem_blk_t))
#define SE_MEM_MIN_BLK (SE_MEM_HDR + SE_MEM_ALIGN)
#define SE_MEM_TAG     0x53450000u
#define SE_MEM_TAG_MSK 0xFFFF0000u

typedef struct mem_blk {
    uint32_t size; /* bytes including this header */
    struct mem_blk *next; /* free: list link. used: SE_MEM_TAG | type */
    uint32_t caller;
    uint32_t seq;
} mem_blk_t;

typedef struct {
    uint8_t *base;
    uint32_t len;
    mem_blk_t *free;
} mem_region_t;

static uint8_t s_main[SE_MEM_MAIN_LEN] __attribute__((aligned(SE_MEM_ALIGN)));

static mem_region_t s_region;
static uint8_t s_mem_ready;
static uint32_t s_seq;

__attribute__((used)) volatile uint32_t se_mem_live;
__attribute__((used)) volatile uint32_t se_mem_blocks;
__attribute__((used)) volatile uint32_t se_mem_peak;
__attribute__((used)) volatile uint32_t se_mem_session_peak;
__attribute__((used)) volatile uint32_t se_mem_idle_live;
__attribute__((used)) volatile uint32_t se_mem_idle_blocks;
__attribute__((used)) volatile uint32_t se_mem_idle_size[SE_MEM_IDLE_LOG];
__attribute__((used)) volatile uint32_t se_mem_idle_type[SE_MEM_IDLE_LOG];
__attribute__((used)) volatile uint32_t se_mem_idle_caller[SE_MEM_IDLE_LOG];
__attribute__((used)) volatile uint32_t se_mem_fail_free_main;
__attribute__((used)) volatile uint32_t se_mem_fail_caller;
__attribute__((used)) volatile uint32_t se_mem_bad_free;
__attribute__((used)) volatile uint32_t se_largest_empty_space;
__attribute__((used)) volatile uint32_t se_mem_free_bytes;
__attribute__((used)) volatile uint32_t se_mem_walk_stop;
__attribute__((used)) volatile uint32_t se_mem_walk_prev_caller;
__attribute__((used)) volatile uint32_t se_mem_walk_prev_size;
__attribute__((used)) volatile uint32_t se_mem_walk_prev_type;
__attribute__((used)) volatile uint32_t se_mem_bad_link;
__attribute__((used)) volatile uint32_t se_mem_bad_addr;
__attribute__((used)) volatile uint32_t se_xmallo_fail_n;
__attribute__((used)) volatile uint32_t se_xmallo_fail_live;
__attribute__((used)) volatile uint32_t se_xmallo_fail_space;
__attribute__((used)) volatile uint32_t se_xmallo_fail_why;
__attribute__((used)) volatile int se_xmallo_fail_type;
__attribute__((used)) volatile uint32_t se_xmallo_mldsa_flags =
#if defined(WOLFSSL_MLDSA_SIGN_SMALL_MEM)
    1u
#else
    0u
#endif
#if defined(WOLFSSL_MLDSA_VERIFY_SMALLEST_MEM)
    | 2u
#endif
#if defined(WOLFSSL_MLDSA_MAKE_KEY_SMALL_MEM)
    | 4u
#endif
    ;

static void region_reset(mem_region_t *r, uint8_t *base, uint32_t len)
{
    r->base = base;
    r->len = len;
    r->free = (mem_blk_t *)base;
    r->free->size = len;
    r->free->next = NULL;
}

static void mem_init(void)
{
    if (s_mem_ready != 0U) {
        return;
    }
    region_reset(&s_region, s_main, SE_MEM_MAIN_LEN);
    s_mem_ready = 1U;
    /* Keep the flag word linked. The debugger watch was dropped by gc. */
    se_xmallo_mldsa_flags |= 0u;
}

static int blk_used(const mem_blk_t *b)
{
    return (((uint32_t)(uintptr_t)b->next & SE_MEM_TAG_MSK) == SE_MEM_TAG) ? 1 : 0;
}

static mem_region_t *region_of(const void *p)
{
    uintptr_t a = (uintptr_t)p;
    uintptr_t base = (uintptr_t)s_region.base;

    if ((a >= base) && (a < base + s_region.len)) {
        return &s_region;
    }
    return NULL;
}

void se_mem_measure(void)
{
    uint8_t *a;
    uint8_t *end;
    uint32_t largest = 0U;
    uint32_t free_sum = 0U;
    uint32_t steps = 0U;

    if ((s_mem_ready == 0U) || (s_region.base == NULL)) {
        se_largest_empty_space = 0U;
        se_mem_free_bytes = 0U;
        se_mem_walk_stop = 0U;
        se_mem_walk_prev_caller = 0U;
        se_mem_walk_prev_size = 0U;
        se_mem_walk_prev_type = 0U;
        return;
    }
    a = s_region.base;
    end = a + s_region.len;
    se_mem_walk_prev_caller = 0U;
    se_mem_walk_prev_size = 0U;
    se_mem_walk_prev_type = 0U;
    while ((a + sizeof(mem_blk_t) <= end) && (steps < 4096U)) {
        const mem_blk_t *b = (const mem_blk_t *)a;

        steps++;
        if ((b->size < SE_MEM_MIN_BLK) || (b->size > (uint32_t)(end - a))) {
            se_mem_walk_stop = (uint32_t)(a - s_region.base);
            se_largest_empty_space = largest;
            se_mem_free_bytes = free_sum;
            return;
        }
        se_mem_walk_prev_caller = b->caller;
        se_mem_walk_prev_size = b->size;
        se_mem_walk_prev_type = (blk_used(b) != 0)
                                    ? ((uint32_t)(uintptr_t)b->next & 0xFFFFu)
                                    : 0U;
        if (blk_used(b) == 0) {
            uint32_t usable = b->size - SE_MEM_HDR;

            free_sum += b->size;
            if (usable > largest) {
                largest = usable;
            }
        }
        a += b->size;
    }
    se_mem_walk_stop = (a == end) ? 0U : (uint32_t)(a - s_region.base);
    se_largest_empty_space = largest;
    se_mem_free_bytes = free_sum;
}

static int region_ptr(const mem_region_t *r, const void *p)
{
    uintptr_t a = (uintptr_t)p;
    uintptr_t base = (uintptr_t)r->base;

    if ((a & 3u) != 0u) {
        return 0;
    }
    return ((a >= base) && (a + sizeof(mem_blk_t) <= base + r->len)) ? 1 : 0;
}

static mem_blk_t *region_take(mem_region_t *r, uint32_t need, int *why, uint32_t *bad)
{
    mem_blk_t *best = NULL;
    mem_blk_t *best_prev = NULL;
    mem_blk_t *prev = NULL;
    mem_blk_t *b;

    *why = 1;
    *bad = 0U;
    b = r->free;
    while (b != NULL) {
        mem_blk_t *nxt;

        if (region_ptr(r, b) == 0) {
            *why = 2;
            *bad = (uint32_t)(uintptr_t)b;
            se_mem_bad_link++;
            if (prev == NULL) {
                r->free = NULL;
            } else {
                prev->next = NULL;
            }
            break;
        }
        if ((b->size < SE_MEM_MIN_BLK) || (b->size > r->len) ||
            ((((uintptr_t)b) & (SE_MEM_ALIGN - 1u)) != 0u) ||
            (((uintptr_t)b + b->size) > ((uintptr_t)r->base + r->len))) {
            *why = 3;
            *bad = (uint32_t)(uintptr_t)b;
            se_mem_bad_link++;
            nxt = NULL;
            if ((b->next != NULL) && (region_ptr(r, b->next) != 0)) {
                nxt = b->next;
            }
            if (prev == NULL) {
                r->free = nxt;
            } else {
                prev->next = nxt;
            }
            b = nxt;
            continue;
        }
        if ((b->next != NULL) && (region_ptr(r, b->next) == 0)) {
            *why = 2;
            *bad = (uint32_t)(uintptr_t)b->next;
            se_mem_bad_link++;
            b->next = NULL;
        }
        if ((b->size >= need) && ((best == NULL) || (b->size < best->size))) {
            best = b;
            best_prev = prev;
        }
        prev = b;
        b = b->next;
    }
    if (best == NULL) {
        return NULL;
    }
    *why = 0;
    if ((best->size - need) >= SE_MEM_MIN_BLK) {
        mem_blk_t *rest = (mem_blk_t *)((uint8_t *)best + need);

        rest->size = best->size - need;
        rest->next = best->next;
        best->size = need;
        if (best_prev == NULL) {
            r->free = rest;
        } else {
            best_prev->next = rest;
        }
    } else if (best_prev == NULL) {
        r->free = best->next;
    } else {
        best_prev->next = best->next;
    }
    return best;
}

static void *mem_alloc_from(size_t n, int type, uint32_t caller)
{
    mem_blk_t *blk;
    uint32_t need = 0U;
    int why = 1;
    uint32_t bad = 0U;

    mem_init();
    if (n > (SE_MEM_MAIN_LEN - SE_MEM_HDR)) {
        blk = NULL;
    } else {
        need = (((uint32_t)n + SE_MEM_ALIGN - 1U) & ~(SE_MEM_ALIGN - 1U)) + SE_MEM_HDR;
        if (need < SE_MEM_MIN_BLK) {
            need = SE_MEM_MIN_BLK;
        }
        blk = region_take(&s_region, need, &why, &bad);
    }
    if (blk == NULL) {
        se_mem_measure();
        if ((why == 1) && ((se_largest_empty_space + SE_MEM_HDR) >= need) && (need != 0U)) {
            why = 4;
        }
        se_xmallo_fail_n = (uint32_t)n;
        se_xmallo_fail_type = type;
        se_xmallo_fail_why = (uint32_t)why;
        se_xmallo_fail_live = se_mem_live;
        se_xmallo_fail_space = se_largest_empty_space;
        se_mem_fail_caller = caller;
        se_mem_fail_free_main = se_largest_empty_space;
        se_mem_bad_addr = bad;
        return NULL;
    }

    blk->next = (mem_blk_t *)(uintptr_t)(SE_MEM_TAG | ((uint32_t)type & 0xFFFFu));
    blk->caller = caller;
    blk->seq = ++s_seq;
    se_mem_live += blk->size;
    se_mem_blocks++;
    if (se_mem_live > se_mem_peak) {
        se_mem_peak = se_mem_live;
    }
    if (se_mem_live > se_mem_session_peak) {
        se_mem_session_peak = se_mem_live;
    }
    se_mem_measure();
    return (uint8_t *)blk + SE_MEM_HDR;
}

void *se_mem_alloc(size_t n, int type)
{
    return mem_alloc_from(n, type, (uint32_t)(uintptr_t)__builtin_return_address(0));
}

void se_mem_free(void *p)
{
    mem_region_t *r;
    mem_blk_t *blk;
    mem_blk_t *prev = NULL;
    mem_blk_t *cur;

    if (p == NULL) {
        return;
    }
    blk = (mem_blk_t *)((uint8_t *)p - SE_MEM_HDR);
    r = region_of(blk);
    if ((r == NULL) || (blk_used(blk) == 0)) {
        se_mem_bad_free++;
        return;
    }
    se_mem_live -= blk->size;
    se_mem_blocks--;

    for (cur = r->free; (cur != NULL) && (cur < blk); prev = cur, cur = cur->next) {
    }
    blk->next = cur;
    if ((cur != NULL) && (((uint8_t *)blk + blk->size) == (uint8_t *)cur)) {
        blk->size += cur->size;
        blk->next = cur->next;
    }
    if (prev == NULL) {
        r->free = blk;
    } else if (((uint8_t *)prev + prev->size) == (uint8_t *)blk) {
        prev->size += blk->size;
        prev->next = blk->next;
    } else {
        prev->next = blk;
    }
    se_mem_measure();
}

static void *mem_realloc_from(void *p, size_t n, int type, uint32_t caller)
{
    mem_blk_t *blk;
    uint32_t have;
    void *np;

    if (p == NULL) {
        return mem_alloc_from(n, type, caller);
    }
    if (n == 0U) {
        se_mem_free(p);
        return NULL;
    }
    blk = (mem_blk_t *)((uint8_t *)p - SE_MEM_HDR);
    if ((region_of(blk) == NULL) || (blk_used(blk) == 0)) {
        se_mem_bad_free++;
        return NULL;
    }
    have = blk->size - SE_MEM_HDR;
    if (n <= have) {
        return p;
    }
    np = mem_alloc_from(n, type, caller);
    if (np == NULL) {
        return NULL;
    }
    (void)memcpy(np, p, have);
    se_mem_free(p);
    return np;
}

void *se_mem_realloc(void *p, size_t n, int type)
{
    return mem_realloc_from(p, n, type, (uint32_t)(uintptr_t)__builtin_return_address(0));
}

void se_mem_reset(void)
{
    (void)memset(s_main, 0, sizeof(s_main));
    region_reset(&s_region, s_main, SE_MEM_MAIN_LEN);
    se_mem_live = 0U;
    se_mem_blocks = 0U;
    se_mem_session_peak = 0U;
    s_mem_ready = 1U;
    se_xmallo_mldsa_flags |= 0u;
    se_mem_measure();
}

void se_mem_session_begin(void)
{
    se_mem_session_peak = se_mem_live;
}

void se_mem_session_end(void)
{
    uint32_t i;
    uint32_t k = 0U;
    uint8_t *a;
    uint8_t *end;

    se_mem_idle_live = se_mem_live;
    se_mem_idle_blocks = se_mem_blocks;
    for (i = 0U; i < SE_MEM_IDLE_LOG; i++) {
        se_mem_idle_size[i] = 0U;
        se_mem_idle_type[i] = 0U;
        se_mem_idle_caller[i] = 0U;
    }
    if (s_mem_ready == 0U) {
        return;
    }
    a = s_region.base;
    end = a + s_region.len;

    while ((a < end) && (k < SE_MEM_IDLE_LOG)) {
        const mem_blk_t *b = (const mem_blk_t *)a;

        if ((b->size < SE_MEM_MIN_BLK) || (b->size > (uint32_t)(end - a))) {
            break;
        }
        if (blk_used(b) != 0) {
            se_mem_idle_size[k] = b->size - SE_MEM_HDR;
            se_mem_idle_type[k] = (uint32_t)(uintptr_t)b->next & 0xFFFFu;
            se_mem_idle_caller[k] = b->caller;
            k++;
        }
        a += b->size;
    }
}

void *XMALLOC(size_t n, void *heap, int type)
{
    (void)heap;
    return mem_alloc_from(n, type, (uint32_t)(uintptr_t)__builtin_return_address(0));
}

void *XREALLOC(void *p, size_t n, void *heap, int type)
{
    (void)heap;
    return mem_realloc_from(p, n, type, (uint32_t)(uintptr_t)__builtin_return_address(0));
}

void XFREE(void *p, void *heap, int type)
{
    (void)heap;
    (void)type;
    se_mem_free(p);
}
