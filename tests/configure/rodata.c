#include "autoconf.h"

int main()
{
#if defined(CONFIG_DEBUG_RODATA) \
    || defined(CONFIG_STRICT_KERNEL_RWX)
  return 1;
#else
  return 0;
#endif
}
