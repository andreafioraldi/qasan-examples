#include "baremetal_x86_1.h"

size_t k_strlen(const char* str) {
	size_t len = 0;
	while (str[len])
		len++;
	return len;
}

void *k_memcpy(void *dest, const void *src, size_t n) {
  size_t i;
  for (i = 0; i < n; ++i)
    ((unsigned char*)dest)[i] = ((unsigned char*)src)[i];
  return dest;
}

char *k_strcpy(char *dest, const char *src) {
  size_t len = k_strlen(src) +1;
  // QASAN_STORE(dest, len);
  return k_memcpy(dest, src, len);
}
