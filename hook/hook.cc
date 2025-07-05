#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "hook.h"
#include <dlfcn.h>
#include <cstdio>
#include <cstdarg>
#include <errno.h>
#include <sys/uio.h>
#include <signal.h>
#include <cstring>
#include <cstdlib>

#include "ff_api.h"
#include "ff_config.h"
#include "ff_epoll.h"
#include "ff_errno.h"
#include "ff_event.h"

// ---------------------------------------------------------------------------
// 日志与辅助宏
// ---------------------------------------------------------------------------
#ifndef HOOK_NO_LOG
#define LOG_CALL(name) fprintf(stdout, "[hook] %s() called\n", #name)
#else
#define LOG_CALL(name)
#endif

// ---------------------------------------------------------------------------
// 1. 定义所有 _sys_xxx 指针（与 hook.h 中 extern 声明对应）
// ---------------------------------------------------------------------------
#define DEFINE_SYS_PTR(type, name, args) type (*_sys_##name) args = nullptr;

// 使用与 hook.h 中 DEC_SYS_API 列表一致的宏，手动实例化。
DEFINE_SYS_PTR(int, socket, (int,int,int));
DEFINE_SYS_PTR(int, socketpair, (int,int,int,int[2]));
DEFINE_SYS_PTR(int, pipe, (int[2]));
DEFINE_SYS_PTR(int, pipe2, (int[2],int));
DEFINE_SYS_PTR(int, fcntl, (int,int,...));
// 手动定义 ioctl，由于其函数签名复杂
decltype(ioctl)* _sys_ioctl = nullptr;
DEFINE_SYS_PTR(int, dup, (int));
DEFINE_SYS_PTR(int, dup2, (int,int));
DEFINE_SYS_PTR(int, dup3, (int,int,int));
DEFINE_SYS_PTR(int, setsockopt, (int,int,int,const void*,socklen_t));
DEFINE_SYS_PTR(int, getsockopt, (int,int,int,void*,socklen_t*));
DEFINE_SYS_PTR(int, close, (int));
DEFINE_SYS_PTR(int, shutdown, (int,int));
DEFINE_SYS_PTR(int, connect, (int,const struct sockaddr*,socklen_t));
DEFINE_SYS_PTR(int, accept, (int,struct sockaddr*,socklen_t*));
DEFINE_SYS_PTR(ssize_t, read, (int,void*,size_t));
DEFINE_SYS_PTR(ssize_t, readv, (int,const struct iovec*,int));
DEFINE_SYS_PTR(ssize_t, recv, (int,void*,size_t,int));
DEFINE_SYS_PTR(ssize_t, recvfrom, (int,void*,size_t,int,struct sockaddr*,socklen_t*));
DEFINE_SYS_PTR(ssize_t, recvmsg, (int,struct msghdr*,int));
DEFINE_SYS_PTR(ssize_t, write, (int,const void*,size_t));
DEFINE_SYS_PTR(ssize_t, writev, (int,const struct iovec*,int));
DEFINE_SYS_PTR(ssize_t, send, (int,const void*,size_t,int));
DEFINE_SYS_PTR(ssize_t, sendto, (int,const void*,size_t,int,const struct sockaddr*,socklen_t));
DEFINE_SYS_PTR(ssize_t, sendmsg, (int,const struct msghdr*,int));
DEFINE_SYS_PTR(int, poll, (struct pollfd*,nfds_t,int));
DEFINE_SYS_PTR(int, select, (int,fd_set*,fd_set*,fd_set*,struct timeval*));
DEFINE_SYS_PTR(unsigned int, sleep, (unsigned int));
DEFINE_SYS_PTR(int, usleep, (useconds_t));
DEFINE_SYS_PTR(int, nanosleep, (const struct timespec*,struct timespec*));
DEFINE_SYS_PTR(struct hostent*, gethostbyname, (const char*));
DEFINE_SYS_PTR(struct hostent*, gethostbyaddr, (const void*,socklen_t,int));
DEFINE_SYS_PTR(int, epoll_wait, (int,struct epoll_event*,int,int));
DEFINE_SYS_PTR(int, accept4, (int,struct sockaddr*,socklen_t*,int));
DEFINE_SYS_PTR(struct hostent*, gethostbyname2, (const char*,int));
DEFINE_SYS_PTR(int, gethostbyname_r, (const char*,struct hostent*,char*,size_t,struct hostent**,int*));
DEFINE_SYS_PTR(int, gethostbyname2_r, (const char*,int,struct hostent*,char*,size_t,struct hostent**,int*));
DEFINE_SYS_PTR(int, gethostbyaddr_r, (const void*,socklen_t,int,struct hostent*,char*,size_t,struct hostent**,int*));
DEFINE_SYS_PTR(int, epoll_create, (int));
DEFINE_SYS_PTR(int, epoll_create1, (int));
DEFINE_SYS_PTR(int, epoll_ctl, (int,int,int,struct epoll_event*));
DEFINE_SYS_PTR(int, epoll_pwait, (int,struct epoll_event*,int,int,const sigset_t*));
DEFINE_SYS_PTR(int, bind, (int,const struct sockaddr*,socklen_t));
DEFINE_SYS_PTR(int, listen, (int,int));
DEFINE_SYS_PTR(int, getsockname, (int,struct sockaddr*,socklen_t*));
DEFINE_SYS_PTR(int, getpeername, (int,struct sockaddr*,socklen_t*));
DEFINE_SYS_PTR(ssize_t, __recv_chk, (int,void*,size_t,size_t,int));
DEFINE_SYS_PTR(ssize_t, __recvfrom_chk, (int,void*,size_t,size_t,int,struct sockaddr*,socklen_t*));
DEFINE_SYS_PTR(ssize_t, __read_chk, (int,void*,size_t,size_t));
DEFINE_SYS_PTR(pid_t, fork, (void));

#undef DEFINE_SYS_PTR

// ---------------------------------------------------------------------------
// 2. 通用宏：加载原始符号并返回指针
// ---------------------------------------------------------------------------
#define LOAD_SYS(name)                                                                    \
    do {                                                                                 \
        if (!_sys_##name) {                                                               \
            _sys_##name = reinterpret_cast<decltype(_sys_##name)>(dlsym(RTLD_NEXT, #name)); \
            if (!_sys_##name) {                                                           \
                fprintf(stdout, "[hook] Failed to resolve symbol %s: %s\n", #name, dlerror()); \
            }                                                                             \
        }                                                                                 \
    } while (0)

// ---------------------------------------------------------------------------
// 3. 生成简单透传的 wrapper；可在这里插入自定义逻辑
// ---------------------------------------------------------------------------
#define WRAP_RET(func, ret_type, args, call_args)          \
    extern "C" __attribute__((weak)) ret_type func args { \
        LOAD_SYS(func);                                    \
        return _sys_##func call_args;                      \
    }

#ifndef likely
#define likely(x)  __builtin_expect(!!(x),1)
#endif

#ifndef unlikely
#define unlikely(x)  __builtin_expect(!!(x),0)
#endif

#define SOCK_FSTACK 0x01000000
#define SOCK_KERNEL 0x02000000

// fstack fd mask
const int FSTACK_FD_MASK = 0x01000000;
// TODO: should be larger
static int ff_kernel_max_fd = 10240;

// ---------------------------------------------------------------------------
// 3A. 显式展开的透传 wrappers（可按需修改内部逻辑）
// ---------------------------------------------------------------------------

extern "C" {
    // 加上 visibility，防止被链接器优化掉
    __attribute__((visibility("default")))
    // fstack 是否在塞 rust 中初始化完成
    int32_t isInit = 0;
}

// check whether the socket should be created by fstack
int
fstack_territory(int domain, int type, int protocol)
{
    /* Remove creation flags */
    // print type
    fprintf(stdout, "[YQ DEBUG]: fstack_territory: type=%d\n", type);
    type &= ~SOCK_CLOEXEC;
    // print type after &= ~SOCK_CLOEXEC
    fprintf(stdout, "[YQ DEBUG]: fstack_territory: type after &= ~SOCK_CLOEXEC=%d\n", type);
    type &= ~SOCK_NONBLOCK;
    // print type after &= ~SOCK_NONBLOCK
    fprintf(stdout, "[YQ DEBUG]: fstack_territory: type after &= ~SOCK_NONBLOCK=%d\n", type);
    type &= ~SOCK_FSTACK;
    type &= ~SOCK_KERNEL;

    if ((AF_INET != domain && AF_INET6 != domain) || (SOCK_STREAM != type &&
        SOCK_DGRAM != type)) {
        return 0;
    }

    return 1;
}

static inline int convert_fstack_fd(int sockfd) {
    return sockfd + ff_kernel_max_fd;
}

static inline int is_fstack_fd(int sockfd) {
    return sockfd >= ff_kernel_max_fd;
}

/* Restore socket fd. */
static inline int restore_fstack_fd(int sockfd) {
    if(sockfd < ff_kernel_max_fd) {
        return sockfd;
    }

    return sockfd - ff_kernel_max_fd;
}

#define CHECK_FD_OWNERSHIP(name, args)                            \
{                                                                 \
    if (!is_fstack_fd(fd)) {                                      \
        return _sys_##name args;                              \
    }                                                             \
    fd = restore_fstack_fd(fd);                                   \
}

#define FF_MAX_FREEBSD_FILES 102400
int fstack_kernel_fd_map[FF_MAX_FREEBSD_FILES];

extern "C" int socket(int domain, int type, int protocol)
{
    LOG_CALL(socket);
    LOAD_SYS(socket);
    
    if (isInit == 0) {
        fprintf(stdout, "[YQ DEBUG]: socket: isInit=%d, run default sys call\n", isInit);
        return _sys_socket(domain, type, protocol);
    }

    // print args
    fprintf(stdout, "[YQ DEBUG]: socket: domain=%d, type=%d, protocol=%d\n", domain, type, protocol);
    
    if (unlikely(fstack_territory(domain, type, protocol) == 0)) {
        // print debug
        fprintf(stdout, "[YQ DEBUG]: fstack_territory failed\n");
        return _sys_socket(domain, type, protocol);
    }

    type &= ~SOCK_FSTACK;
    // print type
    fprintf(stdout, "[YQ DEBUG]: socket: type after &= ~SOCK_FSTACK=%d\n", type);

    // fstack 里面有很多 linux 的宏属性写的有问题, 所以需要创建一个裸的 socket 然后通过 fcntl 来修改属性
    type &= ~SOCK_CLOEXEC;
    type &= ~SOCK_NONBLOCK;
    int ret = ff_socket(domain, type, protocol);

    if (ret >= 0) {
        // print ret as fd
        fprintf(stdout, "[YQ DEBUG]: create ff_socket succesfully: fd=%d\n", ret);

        // 手动添加 CLOEXEC 和 NONBLOCK 属性
        int flags = ff_fcntl(ret, F_GETFD);
        int result = ff_fcntl(ret, F_SETFD, flags | FD_CLOEXEC);
        // 检查 result, 如果有问题打印 error mesage 然后 panic
        if (result < 0) {
            fprintf(stdout, "[YQ DEBUG]: after ff_socket: ff_fcntl set FD_CLOEXEC FAILED, errno:%d, error msg:%s\n", errno, strerror(errno));
            abort();
        }

        int on = 1;
        ff_ioctl(ret, FIONBIO, &on);

        ret = convert_fstack_fd(ret);
    } else {
        // print error info, 然后能不能打出 erro messgae?
        fprintf(stdout, "[YQ DEBUG]: socket: ret=%d, errno=%d, error message: %s\n", ret, errno, strerror(errno));
        // 直接让系统 panic
        abort();
    }

    // print debug
    fprintf(stdout, "[YQ DEBUG]: socket: ret=%d\n", ret);
    return ret;
}

/// bind related ///
#define FF_MAX_BOUND_NUM 1024

struct ff_bound_info {
    int fd;
    struct sockaddr addr;
};

static struct ff_bound_info ff_bound_fds[FF_MAX_BOUND_NUM];

static int
sockaddr_cmp(struct sockaddr *a, const struct sockaddr *b)
{
    struct sockaddr_in *sina, *sinb;
    sina = (struct sockaddr_in *)a;
    sinb = (struct sockaddr_in *)b;

    if (sina->sin_family != sinb->sin_family) {
        return 1;
    }

    if (sina->sin_port != sinb->sin_port) {
        return 1;
    }

    if (sina->sin_addr.s_addr != sinb->sin_addr.s_addr) {
        return 1;
    }

    return 0;
}

static int
sockaddr_is_bound(const struct sockaddr *addr)
{
    int i;

    for (i = 0; i < FF_MAX_BOUND_NUM; i++) {
        struct ff_bound_info *info = &ff_bound_fds[i];
        if (info->fd == 0) {
            continue;
        }

        if (sockaddr_cmp(&info->addr, addr) == 0) {
            return info->fd;
        }
    }

    return 0;
}

static int
sockaddr_bind(int fd, struct sockaddr *addr)
{
    int i;

    for (i = 0; i < FF_MAX_BOUND_NUM; i++) {
        struct ff_bound_info *info = &ff_bound_fds[i];
        if (info->fd != 0) {
            continue;
        }

        info->fd = fd;
        memcpy(&info->addr, addr, sizeof(struct sockaddr));

        return 0;
    }

    return -1;
}

extern "C" int bind(int fd, const struct sockaddr* addr, socklen_t addrlen)
{
    LOG_CALL(bind);
    LOAD_SYS(bind);

    if (isInit == 0) {
        fprintf(stdout, "[YQ DEBUG]: bind: isInit=%d, run default sys call\n", isInit);
        return _sys_bind(fd, addr, addrlen);
    }

    if (addr == NULL) {
        errno = EINVAL;
        return -1;
    }

    CHECK_FD_OWNERSHIP(bind, (fd, addr, addrlen));

    int bound_fd;
    int ret;

    bound_fd = sockaddr_is_bound(addr);
    if (bound_fd != 0 && bound_fd != fd) {
        // print debug
        fprintf(stdout, "[YQ DEBUG]: bind: address already been bind, but bound_fd:%d != fd:%d\n", bound_fd, fd);
        return ff_dup2(bound_fd, fd);
    }

    ret = ff_bind(fd, (struct linux_sockaddr *)addr, addrlen);
    if (ret == 0) {
        sockaddr_bind(fd, (struct sockaddr *)addr);
    }

    fprintf(stdout, "[YQ DEBUG]: bind: fd=%d, ret=%d\n", fd, ret);
    return ret;
}
/// bind related ///

extern "C" int socketpair(int domain, int type, int protocol, int sv[2])
{
    LOG_CALL(socketpair);
    LOAD_SYS(socketpair);
    return _sys_socketpair(domain, type, protocol, sv);
}

extern "C" int pipe(int fds[2])
{
    LOG_CALL(pipe);
    LOAD_SYS(pipe);
    return _sys_pipe(fds);
}

extern "C" int pipe2(int fds[2], int flags)
{
    LOG_CALL(pipe2);
    LOAD_SYS(pipe2);
    return _sys_pipe2(fds, flags);
}

extern "C" int dup(int oldfd)
{
    LOG_CALL(dup);
    LOAD_SYS(dup);
    return _sys_dup(oldfd);
}

extern "C" int dup2(int oldfd, int newfd)
{
    LOG_CALL(dup2);
    LOAD_SYS(dup2);
    return _sys_dup2(oldfd, newfd);
}

extern "C" int dup3(int oldfd, int newfd, int flags)
{
    LOG_CALL(dup3);
    LOAD_SYS(dup3);
    return _sys_dup3(oldfd, newfd, flags);
}

extern "C" int setsockopt(int fd, int level, int optname, const void* optval, socklen_t optlen)
{
    LOG_CALL(setsockopt);
    LOAD_SYS(setsockopt);
    return _sys_setsockopt(fd, level, optname, optval, optlen);
}

/// close related ///
static int
sockaddr_unbind(int fd)
{
    int i;

    for (i = 0; i < FF_MAX_BOUND_NUM; i++) {
        struct ff_bound_info *info = &ff_bound_fds[i];
        if (info->fd != fd) {
            continue;
        }

        info->fd = 0;

    return 0;
}

    return -1;
}

extern "C" int close(int fd)
{
    //LOG_CALL(close);
    LOAD_SYS(close);

    if (isInit == 0) {
        // fprintf(stdout, "[YQ DEBUG]: close: isInit=%d, run default sys call\n", isInit);
        return _sys_close(fd);
    }

    CHECK_FD_OWNERSHIP(close, (fd));

    // print debug
    fprintf(stdout, "[YQ DEBUG]: close: fd=%d\n", fd);

    sockaddr_unbind(fd);
    int ret = ff_close(fd);

    if (ret == 0 && fstack_kernel_fd_map[fd]) {
        // fstack_kernel_fd_map[fd] corresponds to the epoll fd in kernel
        // print debug
        fprintf(stdout, "[YQ DEBUG]: close: fstack_kernel_fd_map[%d]=%d\n", fd, fstack_kernel_fd_map[fd]);
        int kernel_fd_ret = _sys_close(fstack_kernel_fd_map[fd]);
        if (kernel_fd_ret < 0) {
            fprintf(stdout, "[YQ DEBUG]: fstack_kernel_fd_map[%d]=%d, ff_linux_close returns %d, errno=%d\n",
                fd, fstack_kernel_fd_map[fd], kernel_fd_ret, errno);
        } else {
            fstack_kernel_fd_map[fd] = 0;
        }
    }

    fprintf(stdout, "[YQ DEBUG]: close: fd=%d, ret=%d\n", fd, ret);
    return ret;
}
/// close related ///

extern "C" int shutdown(int fd, int how)
{
    LOG_CALL(shutdown);
    LOAD_SYS(shutdown);
    return _sys_shutdown(fd, how);
}

extern "C" int connect(int fd, const struct sockaddr* addr, socklen_t addrlen)
{
    LOG_CALL(connect);
    LOAD_SYS(connect);

    CHECK_FD_OWNERSHIP(connect, (fd, addr, addrlen));

    if (addr == NULL) {
        errno = EINVAL;
        return -1;
    }

    // print debug
    fprintf(stdout, "[YQ DEBUG]: connect: fd=%d, addr=%p, addrlen=%u\n", fd, addr, addrlen);
    
    // print addr data field
    fprintf(stdout, "[YQ DEBUG]: connect: addr->sa_family=%d\n", addr->sa_family);
    // 把 addr-sa_data 的每一位都打出来
    for (int i = 0; i < 14; i++) {
        fprintf(stdout, "[YQ DEBUG]: connect: addr->sa_data[%d]=%d\n", i, ((char *)addr->sa_data)[i]);
    }

    
    int ret = ff_connect(fd, (struct linux_sockaddr *)addr, addrlen);
    if (ret < 0) {
        if (errno == EINPROGRESS) {
            // it's OK for non-blocking socket to return EINPROGRESS
            ret = 0;
        } else {
            fprintf(stdout, "[YQ DEBUG]: connect FAIL: ret=%d, errno=%d, error msg:%s\n", ret, errno, strerror(errno));
            abort();
        }
    }

    // print ret
    fprintf(stdout, "[YQ DEBUG]: connect: ret=%d\n", ret);
    return ret;
}

extern "C" int accept(int sockfd, struct sockaddr* addr, socklen_t* addrlen)
{
    LOG_CALL(accept);
    LOAD_SYS(accept);
    return _sys_accept(sockfd, addr, addrlen);
}

/// read related ///
extern "C" ssize_t read(int fd, void* buf, size_t len)
{
    //LOG_CALL(read);
    LOAD_SYS(read);

    if (isInit == 0) {
        // fprintf(stdout, "[YQ DEBUG]: read: isInit=%d, run default sys call\n", isInit);
        return _sys_read(fd, buf, len);
    }

    CHECK_FD_OWNERSHIP(read, (fd, buf, len));

    if (buf == NULL || len == 0) {
        errno = EINVAL;
        return -1;
    }

    // print debug
    fprintf(stdout, "[YQ DEBUG]: read: fd=%d, buf=%p, count=%zu\n", fd, buf, len);

    int ret = ff_read(fd, buf, len);

    // print debug
    fprintf(stdout, "[YQ DEBUG]: read: ret=%d\n", ret);
    return ret;
}
/// read related ///

extern "C" ssize_t readv(int fd, const struct iovec* iov, int iovcnt)
{
    LOG_CALL(readv);
    LOAD_SYS(readv);
    return _sys_readv(fd, iov, iovcnt);
}

extern "C" ssize_t recv(int fd, void* buf, size_t len, int flags)
{
    LOG_CALL(recv);
    LOAD_SYS(recv);
    
    return recvfrom(fd, buf, len, flags, NULL, NULL);
}

extern "C" ssize_t recvfrom(int fd, void *buf, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen)
{
    LOG_CALL(recvfrom);
    LOAD_SYS(recvfrom);

    if (isInit == 0) {
        fprintf(stdout, "[YQ DEBUG]: recvfrom: isInit=%d, run default sys call\n", isInit);
        return _sys_recvfrom(fd, buf, len, flags, from, fromlen);
    }

    CHECK_FD_OWNERSHIP(recvfrom, (fd, buf, len, flags, from, fromlen));

    if (buf == NULL || len == 0) {
        errno = EINVAL;
        return -1;
    }

    if ((from == NULL && fromlen != NULL) ||
        (from != NULL && fromlen == NULL)) {
        errno = EINVAL;
        return -1;
    }

    int ret = ff_recvfrom(fd, buf, len, flags, (struct linux_sockaddr *)from, fromlen);

    // print debug
    fprintf(stdout, "[YQ DEBUG]: recvfrom: fd=%d, ret=%d\n", fd, ret);
    return ret;
}

extern "C" ssize_t recvmsg(int fd, struct msghdr* msg, int flags)
{
    LOG_CALL(recvmsg);
    LOAD_SYS(recvmsg);
    return _sys_recvmsg(fd, msg, flags);
}

extern "C" ssize_t write(int fd, const void *buf, size_t len)
{
    //LOG_CALL(write);
    LOAD_SYS(write);

    if (isInit == 0) {
        // fprintf(stdout, "[YQ DEBUG]: write: isInit=%d, run default sys call\n", isInit);
        return _sys_write(fd, buf, len);
    }

    CHECK_FD_OWNERSHIP(write, (fd, buf, len));

    // print debug
    fprintf(stdout, "[YQ DEBUG]: write: fd=%d, buf=%p, count=%zu\n", fd, buf, len);

    if (buf == NULL || len == 0) {
        errno = EINVAL;
        return -1;
    }

    int ret = ff_write(fd, buf, len);

    // print debug
    fprintf(stdout, "[YQ DEBUG]: write: ret=%d\n", ret);
    return ret;
}

extern "C" ssize_t writev(int fd, const struct iovec* iov, int iovcnt)
{
    LOG_CALL(writev);
    LOAD_SYS(writev);
    return _sys_writev(fd, iov, iovcnt);
}

extern "C" ssize_t sendto(int fd, const void* buf, size_t len, int flags, const struct sockaddr *to, socklen_t tolen)
{
    LOG_CALL(sendto);
    LOAD_SYS(sendto);

    if (isInit == 0) {
        fprintf(stdout, "[YQ DEBUG]: sendto: isInit=%d, run default sys call\n", isInit);
        return _sys_sendto(fd, buf, len, flags, to, tolen);
    }

    CHECK_FD_OWNERSHIP(sendto, (fd, buf, len, flags, to, tolen));

    if (buf == NULL || len == 0) {
        errno = EINVAL;
        return -1;
    }

    fprintf(stdout, "[YQ DEBUG]: sendto: fd=%d, buf=%p, len=%zu, flags=%d, to=%p, tolen=%d\n", fd, buf, len, flags, to, tolen);
    int ret = ff_sendto(fd, buf, len, flags, (struct linux_sockaddr *)to, tolen);

    fprintf(stdout, "[YQ DEBUG]: sendto: ret=%d\n", ret);
    return ret;
}

extern "C" ssize_t send(int fd, const void* buf, size_t len, int flags)
{
    LOG_CALL(send);
    LOAD_SYS(send);

    return sendto(fd, buf, len, flags, NULL, 0);
}

extern "C" ssize_t sendmsg(int fd, const struct msghdr* msg, int flags)
{
    LOG_CALL(sendmsg);
    LOAD_SYS(sendmsg);
    return _sys_sendmsg(fd, msg, flags);
}

extern "C" int poll(struct pollfd* fds, nfds_t nfds, int timeout)
{
    LOG_CALL(poll);
    LOAD_SYS(poll);
    return _sys_poll(fds, nfds, timeout);
}

extern "C" int select(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, struct timeval* timeout)
{
    LOG_CALL(select);
    LOAD_SYS(select);
    return _sys_select(nfds, readfds, writefds, exceptfds, timeout);
}

extern "C" unsigned int sleep(unsigned int seconds)
{
    LOG_CALL(sleep);
    LOAD_SYS(sleep);
    return _sys_sleep(seconds);
}

extern "C" int usleep(useconds_t usec)
{
    //LOG_CALL(usleep);
    LOAD_SYS(usleep);
    return _sys_usleep(usec);
}

extern "C" int nanosleep(const struct timespec* req, struct timespec* rem)
{
    LOG_CALL(nanosleep);
    LOAD_SYS(nanosleep);
    return _sys_nanosleep(req, rem);
}

extern "C" struct hostent* gethostbyname(const char* name)
{
    LOG_CALL(gethostbyname);
    LOAD_SYS(gethostbyname);
    return _sys_gethostbyname(name);
}

extern "C" struct hostent* gethostbyaddr(const void* addr, socklen_t len, int type)
{
    LOG_CALL(gethostbyaddr);
    LOAD_SYS(gethostbyaddr);
    return _sys_gethostbyaddr(addr, len, type);
}

/// epoll_wait related ///
#define SOCKET_OPS_CONTEXT_MAX_NUM (1 << 5)
#define NS_PER_SECOND  1000000000

extern "C" int epoll_wait(int epfd, struct epoll_event* events, int maxevents, int timeout)
{
    // LOG_CALL(epoll_wait);
    LOAD_SYS(epoll_wait);

    if (isInit == 0) {
        // fprintf(stdout, "[YQ DEBUG]: epoll_wait: isInit=%d, run default sys call\n", isInit);
        return _sys_epoll_wait(epfd, events, maxevents, timeout);
    }

    int fd = epfd;

    CHECK_FD_OWNERSHIP(epoll_wait, (epfd, events, maxevents, timeout));

    // fprintf(stdout, "[YQ DEBUG]: epoll_wait, epfd:%d, maxevents:%d, timeout:%d\n", fd, maxevents, timeout);
    /* maxevents must >= 2, if use FF_KERNEL_EVENT */
    if (unlikely(maxevents < 2)) {
        fprintf(stdout, "[YQ DEBUG]: epoll_wait: maxevents must >= 2, if use FF_KERNEL_EVENT, now is %d\n", maxevents);
        errno = EINVAL;
        return -1;
    }

    int kernel_ret = 0;
    int kernel_maxevents = maxevents / 16;

    if (kernel_maxevents > SOCKET_OPS_CONTEXT_MAX_NUM) {
        kernel_maxevents = SOCKET_OPS_CONTEXT_MAX_NUM;
    } else if (kernel_maxevents <= 0) {
        kernel_maxevents = 1;
    }
    maxevents -= kernel_maxevents;

    // args->epfd = fd;
    // args->events = sh_events;
    // args->maxevents = maxevents;
    // args->timeout = timeout;

    // 首先询问内核有没有任务
    // fprintf(stdout, "[YQ DEBUG]: call _sys_epoll_wait at the same time, epfd:%d, fstack_kernel_fd_map[epfd]:%d, kernel_maxevents:%d\n", fd, fstack_kernel_fd_map[fd], kernel_maxevents);
    if (likely(fstack_kernel_fd_map[fd] > 0)) {
        kernel_ret = _sys_epoll_wait(fstack_kernel_fd_map[fd], events, kernel_maxevents, 0);
        if (kernel_ret < 0) {
            fprintf(stdout, "[YQ DEBUG]: _sys_epoll_wait, kernel_ret:%d, errno:%d, error msg:%s\n", kernel_ret, errno, strerror(errno));
            kernel_ret = 0;
        } else if (kernel_ret > 0) {
            // fprintf(stdout, "[YQ DEBUG]: _sys_epoll_wait get kernel events, kernel_ret:%d\n", kernel_ret);
            
            // // print events
            // for (int i = 0; i < kernel_ret; i++) {
            //     fprintf(stdout, "[YQ DEBUG]: _sys_epoll_wait, events[%d].events:%u, events[%d].data.fd:%d, events[%d].data.u32:%u, events[%d].data.ptr:%p, events[%d].data.u64:%lu\n", i, events[i].events, i, events[i].data.fd, i, events[i].data.u32, i, events[i].data.ptr, i, events[i].data.u64);
            // }
            
            events += kernel_ret;
        }
    }

    // 询问 fstack 有没有任务完成
    int ret = ff_epoll_wait(fd, events, maxevents, timeout);
    // print debug
    if (ret < 0) {
        fprintf(stdout, "[YQ DEBUG]: ff_epoll_wait, ret:%d, errno:%d, error msg:%s\n", ret, errno, strerror(errno));
    } else if (ret > 0) {

        // print events
        for (int i = 0; i < ret; i++) {
            // 需要把 ptr 强制赋值到 u64 中
            events[i].data.u64 = (uint64_t)events[i].data.ptr;

            fprintf(stdout, "[YQ DEBUG]: ff_epoll_wait, events[%d].events:%u, events[%d].data.fd:%d, events[%d].data.u32:%u, events[%d].data.ptr:%p, events[%d].data.u64:%lu\n", i, events[i].events, i, events[i].data.fd, i, events[i].data.u32, i, events[i].data.ptr, i, events[i].data.u64);
        }

        fprintf(stdout, "[YQ DEBUG]: ff_epoll_wait get fstack events, ret:%d\n", ret);
    }

    if (unlikely(kernel_ret > 0)) {
        if (likely(ret > 0)) {
            ret += kernel_ret;
        } else {
            ret = kernel_ret;
        }
    }

    // 注意：调用线程不能被阻塞！！！因为它还要去网卡那边拿取数据

    // print debug
    // fprintf(stdout, "[YQ DEBUG]: epoll_wait, ret:%d\n", ret);
    return ret;
}
/// epoll_wait related ///

extern "C" int epoll_create(int size)
{
    LOG_CALL(epoll_create);
    LOAD_SYS(epoll_create);

    // TODO: we need to store the result of _sys_epoll_create
    if (isInit == 0) {
        fprintf(stdout, "[YQ DEBUG]: epoll_create: isInit=%d, run default sys call\n", isInit);
        return _sys_epoll_create(size);
    }

    fprintf(stdout, "[YQ DEBUG]: before ff_epoll_create\n");
    int ret = ff_epoll_create(1);
    fprintf(stdout, "[YQ DEBUG]: after ff_epoll_create\n");

    if (ret >= 0) {
        // create kernel epoll to manager IO events other than network IO
        int kernel_fd;

        kernel_fd = _sys_epoll_create(1);
        fstack_kernel_fd_map[ret] = kernel_fd;
        fprintf(stdout, "[YQ DEBUG]: epoll_create: fstack fd:%d, FF_KERNEL_EVENT kernel_fd:%d:\n", ret, kernel_fd);
        ret = convert_fstack_fd(ret);
    }

    fprintf(stdout, "[YQ DEBUG]: epoll_create: return fd:%d\n", ret);

    return ret;
}

extern "C" int epoll_create1(int flags)
{
    LOG_CALL(epoll_create1);
    LOAD_SYS(epoll_create1);

    if (isInit == 0) {
        fprintf(stdout, "[YQ DEBUG]: epoll_create1: isInit=%d, run default sys call\n", isInit);
        return _sys_epoll_create1(flags);
    }

    int ret = ff_epoll_create(1);

    if (ret >= 0) {
        // create kernel epoll to manager IO events other than network IO
        int kernel_fd;

        kernel_fd = _sys_epoll_create(1);
        fstack_kernel_fd_map[ret] = kernel_fd;
        fprintf(stdout, "[YQ DEBUG]: epoll_create1: fstack fd:%d, FF_KERNEL_EVENT kernel_fd:%d:\n", ret, kernel_fd);
        ret = convert_fstack_fd(ret);
    }

    fprintf(stdout, "[YQ DEBUG]: epoll_create1: return fd:%d\n", ret);

    return ret;
}

extern "C" int epoll_ctl(int epfd, int op, int fd, struct epoll_event* event)
{
    LOG_CALL(epoll_ctl);
    LOAD_SYS(epoll_ctl);

    fprintf(stdout, "[YQ DEBUG]: enter epoll_ctl, epfd:%d, op:%d, fd:%d\n", epfd, op, fd);
    if (isInit == 0) {
        fprintf(stdout, "[YQ DEBUG]: epoll_ctl: isInit=%d, run default sys call\n", isInit);
        return _sys_epoll_ctl(epfd, op, fd, event);
    }

    int ff_epfd;

    if (unlikely(!is_fstack_fd(fd))) {
        if (is_fstack_fd(epfd)) {
            ff_epfd = restore_fstack_fd(epfd);
            if (likely(fstack_kernel_fd_map[ff_epfd] > 0)) {
                epfd = fstack_kernel_fd_map[ff_epfd];
                fprintf(stdout, "[YQ DEBUG]: epoll_ctl, ff_epfd:%d, kernel epfd:%d\n", ff_epfd, epfd);
            } else {
                fprintf(stdout, "[YQ DEBUG]: epoll_ctl, invalid fd and ff_epfd:%d, epfd:%d, op:%d, fd:%d\n", ff_epfd, epfd, op, fd);
                errno = EBADF;
                return -1;
            }
        }
        // print debug
        fprintf(stdout, "[YQ DEBUG]: epoll_ctl: fd is not fstack fd, epfd:%d, op:%d, fd:%d\n", epfd, op, fd);
        return _sys_epoll_ctl(epfd, op, fd, event);
    }

    fd = restore_fstack_fd(fd);
    ff_epfd = restore_fstack_fd(epfd);

    if ((!event && op != EPOLL_CTL_DEL) ||
        (op != EPOLL_CTL_ADD &&
         op != EPOLL_CTL_MOD &&
         op != EPOLL_CTL_DEL)) {
        errno = EINVAL;
        return -1;
    }

    // print debug
    fprintf(stdout, "[YQ DEBUG]: epoll_ctl, epfd:%d, op:%d, fd:%d, event:%p\n", ff_epfd, op, fd, event);
    
    if (event != NULL) {
        // 由于 fstack 一个很坑的问题，这边需要把 u64 的东西强制再复制一遍到 ptr 中
        event->data.ptr = (void *)event->data.u64;

        fprintf(stdout, "[YQ DEBUG]: epoll_ctl, event->events:%u, event->data.fd:%d, event->data.u32:%u, event->data.ptr:%p, event->data.u64:%lu\n", event->events, event->data.fd, event->data.u32, event->data.ptr, event->data.u64);
    }

    int ret = ff_epoll_ctl(ff_epfd, op, fd, event);

    // print debug
    fprintf(stdout, "[YQ DEBUG]: epoll_ctl: ret=%d\n", ret);
    return ret;
}

extern "C" int epoll_pwait(int epfd, struct epoll_event* events, int maxevents, int timeout, const sigset_t* sigmask)
{
    LOG_CALL(epoll_pwait);
    LOAD_SYS(epoll_pwait);
    return _sys_epoll_pwait(epfd, events, maxevents, timeout, sigmask);
}

extern "C" int accept4(int sockfd, struct sockaddr* addr, socklen_t* addrlen, int flags)
{
    LOG_CALL(accept4);
    LOAD_SYS(accept4);
    return _sys_accept4(sockfd, addr, addrlen, flags);
}

extern "C" struct hostent* gethostbyname2(const char* name, int af)
{
    LOG_CALL(gethostbyname2);
    LOAD_SYS(gethostbyname2);
    return _sys_gethostbyname2(name, af);
}

extern "C" int gethostbyname_r(const char* name, struct hostent* ret, char* buf, size_t len, struct hostent** res, int* err)
{
    LOG_CALL(gethostbyname_r);
    LOAD_SYS(gethostbyname_r);
    return _sys_gethostbyname_r(name, ret, buf, len, res, err);
}

extern "C" int gethostbyname2_r(const char* name, int af, struct hostent* ret, char* buf, size_t len, struct hostent** res, int* err)
{
    LOG_CALL(gethostbyname2_r);
    LOAD_SYS(gethostbyname2_r);
    return _sys_gethostbyname2_r(name, af, ret, buf, len, res, err);
}

extern "C" int gethostbyaddr_r(const void* addr, socklen_t addrlen, int type, struct hostent* ret, char* buf, size_t len, struct hostent** res, int* err)
{
    LOG_CALL(gethostbyaddr_r);
    LOAD_SYS(gethostbyaddr_r);
    return _sys_gethostbyaddr_r(addr, addrlen, type, ret, buf, len, res, err);
}

// ---------------------------------------------------------------------------
// 4. Variadic wrappers (fcntl, ioctl) 需要手动处理 va_list
// ---------------------------------------------------------------------------
extern "C" int fcntl(int fd, int cmd, ...)
{
    //LOG_CALL(fcntl);
    LOAD_SYS(fcntl);

    va_list ap; va_start(ap, cmd);
    unsigned long data = va_arg(ap, unsigned long);
    va_end(ap);

    if (isInit == 0) {
        // fprintf(stdout, "[YQ DEBUG]: fcntl: isInit=%d, run default sys call\n", isInit);
        return _sys_fcntl(fd, cmd, data);
    }

    CHECK_FD_OWNERSHIP(fcntl, (fd, cmd, data));

    // print debug
    fprintf(stdout, "[YQ DEBUG]: fcntl: after CHECK_FD_OWNERSHIP, fd=%d, cmd=%d, data=%lu\n", fd, cmd, data);

    int ret;
    if (cmd == F_DUPFD_CLOEXEC) {
        // if fd is epoll fd, then we need to do some hack, since ff_fcntl cannot set i one step
        int duped_ff_fd =ff_fcntl(fd, F_DUPFD, data);
        // set FD_CLOEXEC
        int flags = ff_fcntl(duped_ff_fd, F_GETFD);
        int result = ff_fcntl(duped_ff_fd, F_SETFD, flags | FD_CLOEXEC);
        // 检查 result, 如果有问题打印 error mesage 然后 panic
        if (result < 0) {
            fprintf(stdout, "[YQ DEBUG]: fcntl: ff_fcntl set FD_CLOEXEC FAILED, errno:%d, error msg:%s\n", errno, strerror(errno));
            abort();
        }

        // we also need to dup corresponding kernel fd
        int duped_kernel_fd = _sys_fcntl(fstack_kernel_fd_map[fd], cmd, data);

        // establish map
        // print debug info
        fprintf(stdout, "[YQ DEBUG]: fcntl: duped_ff_fd:%d, duped_kernel_fd:%d\n", duped_ff_fd, duped_kernel_fd);
        fstack_kernel_fd_map[duped_ff_fd] = duped_kernel_fd;

        ret = convert_fstack_fd(duped_ff_fd);
    } else {
        ret = ff_fcntl(fd, cmd, data);
    }

    // print debug
    fprintf(stdout, "[YQ DEBUG]: fcntl: ret=%d\n", ret);
    return ret;
}

extern "C" int ioctl(int fd, unsigned long req, ...)
{
    // LOG_CALL(ioctl);
    LOAD_SYS(ioctl);
    va_list ap; va_start(ap, req);
    void* data = va_arg(ap, void*);
    va_end(ap);

    if (isInit == 0) {
        // fprintf(stdout, "[YQ DEBUG]: ioctl: isInit=%d, run default sys call\n", isInit);
        return _sys_ioctl(fd, req, data);
    }

    CHECK_FD_OWNERSHIP(ioctl, (fd, req, data));

    if (req != FIOASYNC && req != FIONBIO) {
        errno = ENOTSUP;
        return -1;
    }

    int ret = ff_ioctl(fd, req, data);

    // print debug
    fprintf(stdout, "[YQ DEBUG]: ioctl: fd=%d, req=%ld, data=%p, ret=%d\n", fd, req, data, ret);
    return ret;
}

extern "C" int getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen)
{
    LOG_CALL(getsockopt);
    LOAD_SYS(getsockopt);
    if (isInit == 0) return _sys_getsockopt(fd, level, optname, optval, optlen);
    CHECK_FD_OWNERSHIP(getsockopt, (fd, level, optname, optval, optlen));
    // fstack
    int ret = ff_getsockopt(fd, level, optname, optval, optlen);
    fprintf(stdout, "[YQ DEBUG]: getsockopt: fd=%d, level=%d, optname=%d, optval=%p, optlen=%p, ret=%d\n", fd, level, optname, optval, optlen, ret);
    return ret;
}

extern "C" int listen(int fd, int backlog)
{
    LOG_CALL(listen);
    LOAD_SYS(listen);
    if (isInit == 0) return _sys_listen(fd, backlog);
    CHECK_FD_OWNERSHIP(listen, (fd, backlog));
    // fstack
    int ret = ff_listen(fd, backlog);
    fprintf(stdout, "[YQ DEBUG]: listen: fd=%d, backlog=%d, ret=%d\n", fd, backlog, ret);
    return ret;
}

extern "C" int getsockname(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    LOG_CALL(getsockname);
    LOAD_SYS(getsockname);
    if (isInit == 0) return _sys_getsockname(fd, addr, addrlen);
    CHECK_FD_OWNERSHIP(getsockname, (fd, addr, addrlen));
    int ret = ff_getsockname(fd, (struct linux_sockaddr *)addr, addrlen);
    return ret;
}

extern "C" int getpeername(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    LOG_CALL(getpeername);
    LOAD_SYS(getpeername);
    if (isInit == 0) return _sys_getpeername(fd, addr, addrlen);
    CHECK_FD_OWNERSHIP(getpeername, (fd, addr, addrlen));
    int ret = ff_getpeername(fd, (struct linux_sockaddr *)addr, addrlen);
    return ret;
}

extern "C" ssize_t __recv_chk(int fd, void *buf, size_t len, size_t buflen, int flags)
{
    LOG_CALL(__recv_chk);
    LOAD_SYS(__recv_chk);
    // Simply forward to recv; fortify checks we ignore.
    return _sys___recv_chk(fd, buf, len, buflen, flags);
}

extern "C" ssize_t __recvfrom_chk(int fd, void *buf, size_t len, size_t buflen, int flags, struct sockaddr *from, socklen_t *fromlen)
{
    LOG_CALL(__recvfrom_chk);
    LOAD_SYS(__recvfrom_chk);
    return _sys___recvfrom_chk(fd, buf, len, buflen, flags, from, fromlen);
}

extern "C" ssize_t __read_chk(int fd, void *buf, size_t len, size_t buflen)
{
    LOG_CALL(__read_chk);
    LOAD_SYS(__read_chk);
    return _sys___read_chk(fd, buf, len, buflen);
}

extern "C" pid_t fork(void)
{
    LOG_CALL(fork);
    LOAD_SYS(fork);
    return _sys_fork();
}

// ---------------------------------------------------------------------------
// 6. 一次性解析全部符号，防止并发初始化竞态
// ---------------------------------------------------------------------------

static void init_hook_all()
{
    LOAD_SYS(socket);      LOAD_SYS(socketpair);  LOAD_SYS(pipe);
    LOAD_SYS(pipe2);       LOAD_SYS(fcntl);       LOAD_SYS(ioctl);
    LOAD_SYS(dup);         LOAD_SYS(dup2);        LOAD_SYS(dup3);
    LOAD_SYS(setsockopt);  LOAD_SYS(getsockopt);  LOAD_SYS(close);       LOAD_SYS(shutdown);
    LOAD_SYS(connect);     LOAD_SYS(accept);      LOAD_SYS(read);
    LOAD_SYS(readv);       LOAD_SYS(recv);        LOAD_SYS(recvfrom);
    LOAD_SYS(recvmsg);     LOAD_SYS(write);       LOAD_SYS(writev);
    LOAD_SYS(send);        LOAD_SYS(sendto);      LOAD_SYS(sendmsg);
    LOAD_SYS(poll);        LOAD_SYS(select);      LOAD_SYS(sleep);
    LOAD_SYS(usleep);      LOAD_SYS(nanosleep);   LOAD_SYS(gethostbyname);
    LOAD_SYS(gethostbyaddr); LOAD_SYS(epoll_wait); LOAD_SYS(accept4);
    LOAD_SYS(gethostbyname2); LOAD_SYS(gethostbyname_r);
    LOAD_SYS(gethostbyname2_r); LOAD_SYS(gethostbyaddr_r);
    LOAD_SYS(epoll_create); LOAD_SYS(epoll_create1); LOAD_SYS(epoll_ctl); LOAD_SYS(epoll_pwait);
    LOAD_SYS(bind);
    LOAD_SYS(listen); LOAD_SYS(getsockname); LOAD_SYS(getpeername);
    LOAD_SYS(__recv_chk); LOAD_SYS(__recvfrom_chk); LOAD_SYS(__read_chk);
    LOAD_SYS(fork);
}

__attribute__((constructor)) static void hook_constructor()
{
    // 预热最常用的几个符号，避免多线程竞态
    init_hook_all();
}
