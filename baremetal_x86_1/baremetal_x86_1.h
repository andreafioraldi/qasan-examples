#ifndef BAREMETAL_X86_1_H
#define BAREMETAL_X86_1_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

//utils
size_t k_strlen(const char* str);
void *k_memcpy(void *dest, const void *src, size_t n);
char *k_strcpy(char *dest, const char *src);

//terminal
void k_term_init(void);
void k_putchar(char c);
void k_write(const char* data, size_t size);
void k_print(const char* data);

//malloc
void* k_malloc_orig(size_t);
void k_free_orig(void*);
void* k_malloc_qasan(size_t);
void k_free_qasan(void*);

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

void* qasan_backdoor(int, void*, void*, void*);

#define QASAN_CALL0(action) \
  ((size_t)qasan_backdoor(action, NULL, NULL, NULL))
#define QASAN_CALL1(action, arg1) \
  ((size_t)qasan_backdoor(action, (void*)(arg1), NULL, NULL))
#define QASAN_CALL2(action, arg1, arg2) \
  ((size_t)qasan_backdoor(action, (void*)(arg1), (void*)(arg2), NULL))
#define QASAN_CALL3(action, arg1, arg2, arg3) \
  ((size_t)qasan_backdoor(action, (void*)(arg1), (void*)(arg2), (void*)(arg3)))

#define QASAN_LOAD(ptr, len) \
  QASAN_CALL2(QASAN_ACTION_CHECK_LOAD, ptr, len)
#define QASAN_STORE(ptr, len) \
  QASAN_CALL2(QASAN_ACTION_CHECK_STORE, ptr, len)
#define QASAN_POISON(ptr, len) \
  QASAN_CALL2(QASAN_ACTION_USER_POISON, ptr, len)
#define QASAN_UNPOISON(ptr, len) \
  QASAN_CALL2(QASAN_ACTION_UNPOISON, ptr, len)

#define REDZONE_SIZE 16

// ---------------------------------------

#endif
