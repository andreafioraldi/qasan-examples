/*
 * Copyright (c) 2018-2020, Andreas Kling <kling@serenityos.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Really really *really* Q&D malloc() and free() implementations
 * just to get going. Don't ever let anyone see this shit. :^)
 */

#include <AK/Assertions.h>
#include <AK/Types.h>
#include <Kernel/Arch/i386/CPU.h>
#include <Kernel/KSyms.h>
#include <Kernel/Process.h>
#include <Kernel/Scheduler.h>
#include <Kernel/StdLib.h>
#include <Kernel/Heap/kmalloc.h>

// ---------------------------------------
//  QEMU AddressSanitizer
// ---------------------------------------


enum {
  QASAN_ACTION_CHECK_LOAD,
  QASAN_ACTION_CHECK_STORE,
  QASAN_ACTION_POISON,
  QASAN_ACTION_USER_POISON,
  QASAN_ACTION_UNPOISON,
  QASAN_ACTION_ALLOC,
  QASAN_ACTION_DEALLOC,
  QASAN_ACTION_ENABLE,
  QASAN_ACTION_DISABLE,
  QASAN_ACTION_SWAP_STATE,
};

/* shadow map byte values */
#define ASAN_VALID 0x00
#define ASAN_PARTIAL1 0x01
#define ASAN_PARTIAL2 0x02
#define ASAN_PARTIAL3 0x03
#define ASAN_PARTIAL4 0x04
#define ASAN_PARTIAL5 0x05
#define ASAN_PARTIAL6 0x06
#define ASAN_PARTIAL7 0x07
#define ASAN_ARRAY_COOKIE 0xac
#define ASAN_STACK_RZ 0xf0
#define ASAN_STACK_LEFT_RZ 0xf1
#define ASAN_STACK_MID_RZ 0xf2
#define ASAN_STACK_RIGHT_RZ 0xf3
#define ASAN_STACK_FREED 0xf5
#define ASAN_STACK_OOSCOPE 0xf8
#define ASAN_GLOBAL_RZ 0xf9
#define ASAN_HEAP_RZ 0xe9
#define ASAN_USER 0xf7
#define ASAN_HEAP_LEFT_RZ 0xfa
#define ASAN_HEAP_RIGHT_RZ 0xfb
#define ASAN_HEAP_FREED 0xfd

extern "C" void* qasan_backdoor(int, void*, void*, void*);
asm (
  ".global qasan_backdoor" "\n\t"
  "qasan_backdoor:"        "\n\t"
  "  pushl %edi"           "\n\t"
  "  pushl %esi"           "\n\t"
  "  movl 12(%esp), %eax"  "\n\t" // action
  "  movl 16(%esp), %edi"  "\n\t" // arg1
  "  movl 20(%esp), %esi"  "\n\t" // arg2
  "  movl 24(%esp), %edx"  "\n\t" // arg3
  "  .byte 0x0f"           "\n\t"
  "  .byte 0x3a"           "\n\t"
  "  .byte 0xf2"           "\n\t"
  "  popl %esi"            "\n\t"
  "  popl %esi"            "\n\t"
  "  popl %edi"            "\n\t"
  "  ret"                  "\n\t"
);

#define QASAN_CALL0(action) \
  ((size_t)qasan_backdoor(action, 0, 0, 0))
#define QASAN_CALL1(action, arg1) \
  ((size_t)qasan_backdoor(action, (void*)(arg1), 0, 0))
#define QASAN_CALL2(action, arg1, arg2) \
  ((size_t)qasan_backdoor(action, (void*)(arg1), (void*)(arg2), 0))
#define QASAN_CALL3(action, arg1, arg2, arg3) \
  ((size_t)qasan_backdoor(action, (void*)(arg1), (void*)(arg2), (void*)(arg3)))

#define QASAN_LOAD(ptr, len) \
  QASAN_CALL2(QASAN_ACTION_CHECK_LOAD, ptr, len)
#define QASAN_STORE(ptr, len) \
  QASAN_CALL2(QASAN_ACTION_CHECK_STORE, ptr, len)

#define QASAN_POISON(ptr, len, poison_byte) \
  QASAN_CALL3(QASAN_ACTION_POISON, ptr, len, poison_byte)
#define QASAN_USER_POISON(ptr, len) \
  QASAN_CALL2(QASAN_ACTION_USER_POISON, ptr, len)
#define QASAN_UNPOISON(ptr, len) \
  QASAN_CALL2(QASAN_ACTION_UNPOISON, ptr, len)

#define QASAN_ALLOC(start, end) \
  QASAN_CALL2(QASAN_ACTION_ALLOC, start, end)
#define QASAN_DEALLOC(ptr) \
  QASAN_CALL1(QASAN_ACTION_DEALLOC, ptr)

#define QASAN_SWAP(state) \
  QASAN_CALL1(QASAN_ACTION_SWAP_STATE, state)

#define REDZONE_SIZE 32

// ---------------------------------------

// #define SANITIZE_KMALLOC

struct [[gnu::packed]] allocation_t
{
    size_t start;
    size_t nchunk;
    size_t qasan_size;
    size_t _pad;
};

#define BASE_PHYSICAL (0xc0000000 + (4 * MB))
#define CHUNK_SIZE 8
#define POOL_SIZE (3 * MB)

#define ETERNAL_BASE_PHYSICAL (0xc0000000 + (2 * MB))
#define ETERNAL_RANGE_SIZE (2 * MB)

static u8 alloc_map[POOL_SIZE / CHUNK_SIZE / 8];

volatile size_t sum_alloc = 0;
volatile size_t sum_free = POOL_SIZE;
volatile size_t kmalloc_sum_eternal = 0;

u32 g_kmalloc_call_count;
u32 g_kfree_call_count;
bool g_dump_kmalloc_stacks;

static u8* s_next_eternal_ptr;
static u8* s_end_of_eternal_range;

bool is_kmalloc_address(const void* ptr)
{
    if (ptr >= (u8*)ETERNAL_BASE_PHYSICAL && ptr < s_next_eternal_ptr)
        return true;
    return (size_t)ptr >= BASE_PHYSICAL && (size_t)ptr <= (BASE_PHYSICAL + POOL_SIZE);
}

void kmalloc_init()
{
    memset(&alloc_map, 0, sizeof(alloc_map));
    
    // this routine is called more than one time
    // Serenity uses Triple fault to reboot sveral times at startup
    QASAN_UNPOISON((void*)BASE_PHYSICAL, POOL_SIZE);
    
    memset((void*)BASE_PHYSICAL, 0, POOL_SIZE);

    kmalloc_sum_eternal = 0;
    sum_alloc = 0;
    sum_free = POOL_SIZE;

    s_next_eternal_ptr = (u8*)ETERNAL_BASE_PHYSICAL;
    s_end_of_eternal_range = s_next_eternal_ptr + ETERNAL_RANGE_SIZE;
}

void* kmalloc_eternal(size_t size)
{
    void* ptr = s_next_eternal_ptr;
    s_next_eternal_ptr += size;
    ASSERT(s_next_eternal_ptr < s_end_of_eternal_range);
    kmalloc_sum_eternal += size;
    return ptr;
}

void* kmalloc_aligned(size_t size, size_t alignment)
{
    void* ptr = kmalloc(size + alignment + sizeof(void*));
    size_t max_addr = (size_t)ptr + alignment;
    void* aligned_ptr = (void*)(max_addr - (max_addr % alignment));
    ((void**)aligned_ptr)[-1] = ptr;
    return aligned_ptr;
}

void kfree_aligned(void* ptr)
{
    kfree(((void**)ptr)[-1]);
}

void* kmalloc_page_aligned(size_t size)
{
    void* ptr = kmalloc_aligned(size, PAGE_SIZE);
    size_t d = (size_t)ptr;
    ASSERT((d & PAGE_MASK) == d);
    return ptr;
}

void* kmalloc_impl(size_t size)
{
    InterruptDisabler disabler;
    ++g_kmalloc_call_count;

    if (g_dump_kmalloc_stacks && ksyms_ready) {
        dbgprintf("kmalloc(%u)\n", size);
        dump_backtrace();
    }

    // We need space for the allocation_t structure at the head of the block.
    size_t real_size = size + sizeof(allocation_t) + REDZONE_SIZE*2;

    if (sum_free < real_size) {
        dump_backtrace();
        kprintf("%s(%u) kmalloc(): PANIC! Out of memory (sucks, dude)\nsum_free=%u, real_size=%u\n", current->process().name().characters(), current->pid(), sum_free, real_size);
        hang();
    }

    size_t chunks_needed = real_size / CHUNK_SIZE;
    if (real_size % CHUNK_SIZE)
        ++chunks_needed;

    size_t chunks_here = 0;
    size_t first_chunk = 0;

    for (size_t i = 0; i < (POOL_SIZE / CHUNK_SIZE / 8); ++i) {
        if (alloc_map[i] == 0xff) {
            // Skip over completely full bucket.
            chunks_here = 0;
            continue;
        }
        // FIXME: This scan can be optimized further with LZCNT.
        for (size_t j = 0; j < 8; ++j) {
            if (!(alloc_map[i] & (1 << j))) {
                if (chunks_here == 0) {
                    // Mark where potential allocation starts.
                    first_chunk = i * 8 + j;
                }

                ++chunks_here;

                if (chunks_here == chunks_needed) {
                    auto* a = (allocation_t*)(BASE_PHYSICAL + (first_chunk * CHUNK_SIZE));
                    QASAN_UNPOISON(a, chunks_needed * CHUNK_SIZE);
                    
                    u8* ptr = (u8*)a;
                    ptr += sizeof(allocation_t);
                    a->nchunk = chunks_needed;
                    a->start = first_chunk;
                    a->qasan_size = size;

                    for (size_t k = first_chunk; k < (first_chunk + chunks_needed); ++k) {
                        alloc_map[k / 8] |= 1 << (k % 8);
                    }

                    sum_alloc += a->nchunk * CHUNK_SIZE;
                    sum_free -= a->nchunk * CHUNK_SIZE;
#ifdef SANITIZE_KMALLOC
                    memset(ptr, 0xbb, (a->nchunk * CHUNK_SIZE) - sizeof(allocation_t));
#endif
                    u8* r_ptr = ptr + REDZONE_SIZE;
                    QASAN_POISON(ptr, REDZONE_SIZE, ASAN_HEAP_LEFT_RZ);
                    QASAN_POISON(r_ptr + size, chunks_needed * CHUNK_SIZE -size -REDZONE_SIZE -sizeof(allocation_t), ASAN_HEAP_RIGHT_RZ);
                    QASAN_ALLOC(r_ptr, r_ptr + size);
                    return r_ptr;
                }
            } else {
                // This is in use, so restart chunks_here counter.
                chunks_here = 0;
            }
        }
    }

    kprintf("%s(%u) kmalloc(): PANIC! Out of memory (no suitable block for size %u)\n", current->process().name().characters(), current->pid(), size);
    dump_backtrace();
    hang();
}

void kfree(void* ptr)
{
    if (!ptr)
        return;

    InterruptDisabler disabler;
    ++g_kfree_call_count;

    auto* a = (allocation_t*)((((u8*)ptr) - sizeof(allocation_t) - REDZONE_SIZE));

    for (size_t k = a->start; k < (a->start + a->nchunk); ++k)
        alloc_map[k / 8] &= ~(1 << (k % 8));

    sum_alloc -= a->nchunk * CHUNK_SIZE;
    sum_free += a->nchunk * CHUNK_SIZE;

#ifdef SANITIZE_KMALLOC
    memset(a, 0xaa, a->nchunk * CHUNK_SIZE);
#endif
    QASAN_DEALLOC(ptr);
    QASAN_POISON(a, a->nchunk * CHUNK_SIZE, ASAN_HEAP_FREED);

    //*(char*)ptr=0; // fake bug
}

void* krealloc(void* ptr, size_t new_size)
{
    if (!ptr)
        return kmalloc(new_size);

    InterruptDisabler disabler;

    auto* a = (allocation_t*)((((u8*)ptr) - sizeof(allocation_t) - REDZONE_SIZE));
    size_t old_size = a->qasan_size;

    if (old_size == new_size)
        return ptr;

    auto* new_ptr = kmalloc(new_size);
    memcpy(new_ptr, ptr, min(old_size, new_size));
    kfree(ptr);
    return new_ptr;
}

void* operator new(size_t size)
{
    return kmalloc(size);
}

void* operator new[](size_t size)
{
    return kmalloc(size);
}

void operator delete(void* ptr)
{
    return kfree(ptr);
}

void operator delete[](void* ptr)
{
    return kfree(ptr);
}

void operator delete(void* ptr, size_t)
{
    return kfree(ptr);
}

void operator delete[](void* ptr, size_t)
{
    return kfree(ptr);
}
