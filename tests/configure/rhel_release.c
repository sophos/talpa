#include <stdio.h>

#include "autoconf.h"
#include "linux/version.h"

int main()
{
  printf("%u", RHEL_RELEASE_CODE);

  return 0;
}
