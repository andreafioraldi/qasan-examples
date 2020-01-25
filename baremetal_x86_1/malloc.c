#include "baremetal_x86_1.h"

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

#define GET_BIT(_ar, _b) \
  !!((((unsigned char *)(_ar))[(_b) >> 3] & (128 >> ((_b)&7))))

#define FLIP_BIT(_ar, _b)                          \
  do {                                             \
                                                   \
    unsigned char *_arf = (unsigned char *)(_ar);  \
    unsigned int _bf  = (_b);                      \
    _arf[(_bf) >> 3] ^= (128 >> ((_bf)&7));        \
                                                   \
  } while (0)

#define POOL_SIZE 256

struct chunk {
  char _p[32];
};

struct chunk pool[POOL_SIZE];
unsigned char bitmap[POOL_SIZE / 8];

void * k_malloc_orig(size_t s) {

  size_t size = ((s+sizeof(unsigned short)) | 31)+1; // add metadata and pad to 32
  size_t num = size / sizeof(struct chunk);
  
  size_t max = 0;
  int i;
  for (i = 0; i < POOL_SIZE; ++i) {
    if (GET_BIT(bitmap, i)) {
      max = 0;
    } else {
      max += 1;
      if (max == num) {
        int j = (i+1)-num;
        unsigned short * m = (unsigned short*)&pool[j];
        while (j <= i)
          FLIP_BIT(bitmap, j++);
        m[0] = num;
        return &m[1];
      }
    }
  }
  
  return 0;

}

void k_free_orig(void* p) {

  unsigned short* m = p;
  m -= 1;
  
  int i = (struct chunk*)m - pool;
  int j;
  for (j = 0; j < m[0]; ++j)
    FLIP_BIT(bitmap, j+i);

}

void * k_malloc_qasan(size_t s) {

  size_t size = ((s+sizeof(unsigned short) + REDZONE_SIZE*2) | 31)+1; // add metadata and pad to 32
  size_t num = size / sizeof(struct chunk);
  
  size_t max = 0;
  int i;
  for (i = 0; i < POOL_SIZE; ++i) {
    if (GET_BIT(bitmap, i)) {
      max = 0;
    } else {
      max += 1;
      if (max == num) {
        int j = (i+1)-num;
        unsigned char * m = (unsigned char*)&pool[j];
        unsigned char * rm = m + sizeof(unsigned short) + REDZONE_SIZE;
        QASAN_UNPOISON(m, size);
        while (j <= i)
          FLIP_BIT(bitmap, j++);
        *((unsigned short*)m) = num;
        QASAN_POISON(m + sizeof(unsigned short), REDZONE_SIZE);
        QASAN_POISON(rm + s, REDZONE_SIZE);
        QASAN_UNPOISON(rm, s);
        return rm;
      }
    }
  }
  
  return 0;

}

void k_free_qasan(void* p) {

  unsigned short* m = (unsigned short*)((unsigned char*)p - (sizeof(unsigned short) + REDZONE_SIZE));
  int num = m[0];
  
  int i = (struct chunk*)m - pool;
  int j;
  for (j = 0; j < num; ++j)
    FLIP_BIT(bitmap, j+i);

  QASAN_POISON(m, num*sizeof(struct chunk));

}
