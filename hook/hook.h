#pragma once

#define __sys_api(x)        _sys_##x
#define DEC_SYS_API(x)  extern x##_fp_t __sys_api(x)

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <poll.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <time.h>
#include <signal.h>

#define DEF_SYS_API(x)  x##_fp_t __sys_api(x) = 0

extern "C" {
typedef int (*socket_fp_t)(int, int, int);
typedef int (*socketpair_fp_t)(int, int, int, int [2]);
typedef int (*pipe_fp_t)(int [2]);
typedef int (*pipe2_fp_t)(int [2], int);
typedef int (*fcntl_fp_t)(int, int, ...);
typedef decltype(ioctl)* ioctl_fp_t;
typedef int (*dup_fp_t)(int);
typedef int (*dup2_fp_t)(int, int);
typedef int (*dup3_fp_t)(int, int, int);
typedef int (*setsockopt_fp_t)(int, int, int, const void*, socklen_t);
typedef int (*getsockopt_fp_t)(int, int, int, void*, socklen_t*);

typedef int (*close_fp_t)(int);
typedef int (*shutdown_fp_t)(int, int);
typedef int (*connect_fp_t)(int, const struct sockaddr*, socklen_t);
typedef int (*accept_fp_t)(int, struct sockaddr*, socklen_t*);
typedef int (*bind_fp_t)(int, const struct sockaddr*, socklen_t);
typedef ssize_t (*read_fp_t)(int, void*, size_t);
typedef ssize_t (*readv_fp_t)(int, const struct iovec*, int);
typedef ssize_t (*recv_fp_t)(int, void*, size_t, int);
typedef ssize_t (*recvfrom_fp_t)(int, void*, size_t, int, struct sockaddr*, socklen_t*);
typedef ssize_t (*recvmsg_fp_t)(int, struct msghdr*, int);
typedef ssize_t (*write_fp_t)(int, const void*, size_t);
typedef ssize_t (*writev_fp_t)(int, const struct iovec*, int);
typedef ssize_t (*send_fp_t)(int, const void*, size_t, int);
typedef ssize_t (*sendto_fp_t)(int, const void*, size_t, int, const struct sockaddr*, socklen_t);
typedef ssize_t (*sendmsg_fp_t)(int, const struct msghdr*, int);
typedef int (*poll_fp_t)(struct pollfd*, nfds_t, int);
typedef int (*select_fp_t)(int, fd_set*, fd_set*, fd_set*, struct timeval*);
typedef unsigned int (*sleep_fp_t)(unsigned int);
typedef int (*usleep_fp_t)(useconds_t);
typedef int (*nanosleep_fp_t)(const struct timespec*, struct timespec*);
typedef struct hostent* (*gethostbyname_fp_t)(const char*);
typedef struct hostent* (*gethostbyaddr_fp_t)(const void*, socklen_t, int);

typedef int (*epoll_wait_fp_t)(int, struct epoll_event*, int, int);
typedef int (*epoll_create_fp_t)(int);
typedef int (*epoll_create1_fp_t)(int);
typedef int (*epoll_ctl_fp_t)(int,int,int,struct epoll_event*);
typedef int (*epoll_pwait_fp_t)(int, struct epoll_event*, int, int, const sigset_t*);
typedef int (*accept4_fp_t)(int, struct sockaddr*, socklen_t*, int);
typedef struct hostent* (*gethostbyname2_fp_t)(const char*, int);
typedef int (*gethostbyname_r_fp_t)(const char*, struct hostent*, char*, size_t, struct hostent**, int*);
typedef int (*gethostbyname2_r_fp_t)(const char*, int, struct hostent*, char*, size_t, struct hostent**, int*);
typedef int (*gethostbyaddr_r_fp_t)(const void*, socklen_t, int, struct hostent*, char*, size_t, struct hostent**,
                                    int*);
typedef int (*kevent_fp_t)(int, const struct kevent*, int, struct kevent*, int, const struct timespec*);

typedef int (*listen_fp_t)(int, int);
typedef int (*getsockname_fp_t)(int, struct sockaddr*, socklen_t*);
typedef int (*getpeername_fp_t)(int, struct sockaddr*, socklen_t*);
typedef ssize_t (*__recv_chk_fp_t)(int, void*, size_t, size_t, int);
typedef ssize_t (*__recvfrom_chk_fp_t)(int, void*, size_t, size_t, int, struct sockaddr*, socklen_t*);
typedef ssize_t (*__read_chk_fp_t)(int, void*, size_t, size_t);
typedef pid_t (*fork_fp_t)(void);

DEC_SYS_API(socket);
DEC_SYS_API(socketpair);
DEC_SYS_API(bind);
DEC_SYS_API(pipe);
DEC_SYS_API(pipe2);
DEC_SYS_API(fcntl);
DEC_SYS_API(ioctl);
DEC_SYS_API(dup);
DEC_SYS_API(dup2);
DEC_SYS_API(dup3);
DEC_SYS_API(setsockopt);
DEC_SYS_API(getsockopt);

DEC_SYS_API(close);
DEC_SYS_API(shutdown);
DEC_SYS_API(connect);
DEC_SYS_API(accept);
DEC_SYS_API(read);
DEC_SYS_API(readv);
DEC_SYS_API(recv);
DEC_SYS_API(recvfrom);
DEC_SYS_API(recvmsg);
DEC_SYS_API(write);
DEC_SYS_API(writev);
DEC_SYS_API(send);
DEC_SYS_API(sendto);
DEC_SYS_API(sendmsg);
DEC_SYS_API(poll);
DEC_SYS_API(select);
DEC_SYS_API(sleep);
DEC_SYS_API(usleep);
DEC_SYS_API(nanosleep);
DEC_SYS_API(gethostbyname);
DEC_SYS_API(gethostbyaddr);

DEC_SYS_API(epoll_wait);
DEC_SYS_API(epoll_create);
DEC_SYS_API(epoll_create1);
DEC_SYS_API(epoll_ctl);
DEC_SYS_API(epoll_pwait);
DEC_SYS_API(accept4);
DEC_SYS_API(gethostbyname2);
DEC_SYS_API(gethostbyname_r);
DEC_SYS_API(gethostbyname2_r);
DEC_SYS_API(gethostbyaddr_r);
DEC_SYS_API(kevent);

DEC_SYS_API(listen);
DEC_SYS_API(getsockname);
DEC_SYS_API(getpeername);
DEC_SYS_API(__recv_chk);
DEC_SYS_API(__recvfrom_chk);
DEC_SYS_API(__read_chk);
DEC_SYS_API(fork);
} // "C"

// Provide generic macro helpers for declaring system API pointers
// HOOK_DECLARE(ret_type, name, args)
//   declares typedef for pointer and extern variable _sys_name
//   example: HOOK_DECLARE(int, close, (int));
#ifndef HOOK_DECLARE
#define HOOK_DECLARE(ret, name, args) \
    typedef ret (*name##_fp_t) args;  \
    extern name##_fp_t _sys_##name
#endif
