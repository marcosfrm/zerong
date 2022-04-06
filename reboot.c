#include <signal.h>

int main(void)
{
    return !!kill(1, SIGINT);
}
