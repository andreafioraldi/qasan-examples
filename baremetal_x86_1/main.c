#include "baremetal_x86_1.h"

void kernel_main(void) {

  k_term_init();
  k_print("fullsystem-qasan-tests: baremetal_x86_1\n");

  char * a = k_malloc_qasan(16);
  k_strcpy(a, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n");
  k_print(a);
  k_free_qasan(a);

  k_print("done.");

}
