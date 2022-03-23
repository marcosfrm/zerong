#define _FILE_OFFSET_BITS 64

#include <fcntl.h>
#include <signal.h>
#include <unistd.h>

int main(void)
{
    int fd;
    pid_t ppid;

    fd = open("/run/zerong-poweroff", O_WRONLY|O_CREAT, 0600);
    if (fd >= 0)
    {
        close(fd);
    }

    ppid = getppid();

    return !!kill(ppid, SIGHUP);
}
