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
  QASAN_ACTION_UNPOISON,
};

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
#define QASAN_POISON(ptr, len) \
  QASAN_CALL2(QASAN_ACTION_POISON, ptr, len)
#define QASAN_UNPOISON(ptr, len) \
  QASAN_CALL2(QASAN_ACTION_UNPOISON, ptr, len)

#define REDZONE_SIZE 32

// ---------------------------------------

#define SANITIZE_KMALLOC

struct [[gnu::packed]] allocation_t
{
    size_t start;
    size_t nchunk;
};

#define BASE_PHYSICAL (4 * MB)
#define CHUNK_SIZE 8
#define POOL_SIZE (3 * MB)

#define ETERNAL_BASE_PHYSICAL (2 * MB)
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
    size_t real_size = size + (REDZONE_SIZE*2) + sizeof(allocation_t);

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

                    for (size_t k = first_chunk; k < (first_chunk + chunks_needed); ++k) {
                        alloc_map[k / 8] |= 1 << (k % 8);
                    }

                    sum_alloc += a->nchunk * CHUNK_SIZE;
                    sum_free -= a->nchunk * CHUNK_SIZE;
#ifdef SANITIZE_KMALLOC
                    memset(ptr, 0xbb, (a->nchunk * CHUNK_SIZE) - sizeof(allocation_t));
#endif

                    QASAN_POISON(ptr, REDZONE_SIZE);
                    QASAN_POISON(ptr + REDZONE_SIZE + size, REDZONE_SIZE);
                    return ptr + REDZONE_SIZE;
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
    QASAN_UNPOISON(a, a->nchunk * CHUNK_SIZE);
    memset(a, 0xaa, a->nchunk * CHUNK_SIZE);
#endif
    QASAN_POISON(a, a->nchunk * CHUNK_SIZE);
}

void* krealloc(void* ptr, size_t new_size)
{
    if (!ptr)
        return kmalloc(new_size);

    InterruptDisabler disabler;

    auto* a = (allocation_t*)((((u8*)ptr) - sizeof(allocation_t) - REDZONE_SIZE));
    size_t old_size = a->nchunk * CHUNK_SIZE;

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
