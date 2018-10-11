#include <sys/mount.h>
#include <errno.h>

int main()
{
    if ( mount("/dev/non-existant-device", "/mnt", "ext2", 0, 0) )
    {
        if ( errno == ENOENT )
        {
            return 0;
        }
    }

    return 1;
}

