/* Use the SDK's structure layouts rather than duplicating private libproc ABIs in Rust. */
#include <libproc.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>

/* 0: other, 1: IP socket, 2: vnode path, 3: descriptor vanished, -1: incomplete. */
int cb_monitor_descriptor(int pid, int fd, unsigned int kind, char *path, unsigned int capacity) {
    if (kind == PROX_FDTYPE_SOCKET) {
        struct socket_fdinfo info = {0};
        errno = 0;
        int n = proc_pidfdinfo(pid, fd, PROC_PIDFDSOCKETINFO, &info, sizeof(info));
        if (n != sizeof(info)) return errno == EBADF || errno == ESRCH || errno == ENOENT ? 3 : -1;
        if (info.psi.soi_family != AF_INET && info.psi.soi_family != AF_INET6) return 0;
        /* Ignore unused/listening sockets. A remote peer is an observation, not proof of intent. */
        if (info.psi.soi_kind == SOCKINFO_TCP) return info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_fport != 0 ? 1 : 0;
        if (info.psi.soi_kind == SOCKINFO_IN) return info.psi.soi_proto.pri_in.insi_fport != 0 ? 1 : 0;
        return -1;
    }
    if (kind == PROX_FDTYPE_VNODE) {
        struct vnode_fdinfowithpath info = {0};
        errno = 0;
        int n = proc_pidfdinfo(pid, fd, PROC_PIDFDVNODEPATHINFO, &info, sizeof(info));
        if (n != sizeof(info)) return errno == EBADF || errno == ESRCH || errno == ENOENT ? 3 : -1;
        size_t length = strnlen(info.pvip.vip_path, sizeof(info.pvip.vip_path));
        if (length == sizeof(info.pvip.vip_path) || length + 1 > capacity) return -1;
        memcpy(path, info.pvip.vip_path, length);
        path[length] = 0;
        return 2;
    }
    return 0;
}
