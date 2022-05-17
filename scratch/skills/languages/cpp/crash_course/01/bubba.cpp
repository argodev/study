#include <cstdio>
#include <fcntl.h>
#include <cstring>
#include <unistd.h>

typedef unsigned int uint;
typedef char byte;

int main(int argc, char** argv) {
    int fd01 = 0;
    int num_bytes = 0;
    int bytes_written = 0;
//    fd01 = open("/home/ru7/workspace/ru7/study/wd01", 0x1002);
    fd01 = open("/home/ru7/workspace/ru7/study/wd01", 0x02);

    char buff[16];

    for (int i = 0; i < 16; i++) {
        buff[i] = 0;
    }

    sprintf(buff, "0x%x", (uint)(byte)(0xf0));
    num_bytes = strlen(buff);
    bytes_written = write(fd01, buff, num_bytes);
    printf("%s\n", buff);
    close(fd01);

    sprintf(buff, "0x%x", (uint)(byte)(0x82));
    printf("%s\n", buff);

    sprintf(buff, "0x%x", (uint)(byte)(0x96));
    printf("%s\n", buff);

    sprintf(buff, "0x%x", (uint)(byte)(0x05));
    printf("%s\n", buff);

    sprintf(buff, "0x%x", (uint)(byte)(0x36));
    printf("%s\n", buff);

    return 0;
}