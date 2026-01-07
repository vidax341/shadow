#ifndef SHADOW_H
#define SHADOW_H

#include <linux/ftrace.h>
#include <linux/linkage.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/kprobes.h>


/* Function pointer types for ftrace core functions */
typedef int (*ftrace_set_filter_ip_t)(struct ftrace_ops *ops, unsigned long ip, int remove, int reset);
typedef int (*register_ftrace_function_t)(struct ftrace_ops *ops);
typedef int (*unregister_ftrace_function_t)(struct ftrace_ops *ops);

static ftrace_set_filter_ip_t _ftrace_set_filter_ip;
static register_ftrace_function_t _register_ftrace_function;
static unregister_ftrace_function_t _unregister_ftrace_function;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
static unsigned long lookup_name(const char *name)
{
    struct kprobe kp = {
        .symbol_name = name
    };
    unsigned long retval;

    if (register_kprobe(&kp) < 0) return 0;
    retval = (unsigned long) kp.addr;
    unregister_kprobe(&kp);
    return retval;
}
#else
static unsigned long lookup_name(const char *name)
{
    return kallsyms_lookup_name(name);
}
#endif

/* Resolve ftrace core functions dynamically */
static int resolve_ftrace_functions(void)
{
    _ftrace_set_filter_ip = (ftrace_set_filter_ip_t)lookup_name("ftrace_set_filter_ip");
    _register_ftrace_function = (register_ftrace_function_t)lookup_name("register_ftrace_function");
    _unregister_ftrace_function = (unregister_ftrace_function_t)lookup_name("unregister_ftrace_function");

    if (!_ftrace_set_filter_ip || !_register_ftrace_function || !_unregister_ftrace_function) {
        pr_err("Failed to resolve ftrace core functions\n");
        return -ENOENT;
    }
    return 0;
}

struct ftrace_hook {
    const char *name;
    void *function;
    void *original;
    unsigned long address;
    struct ftrace_ops ops;
};

static int fh_resolve_symbol(struct ftrace_hook *hook)
{
    hook->address = lookup_name(hook->name);

    if (!hook->address) {
        pr_err("unresolved symbol: %s\n", hook->name);
        return -ENOENT;
    }

    *((unsigned long*) hook->original) = hook->address;

    return 0;
}

static void fh_set_ip(struct ftrace_regs *fregs, unsigned long ip)
{
    struct pt_regs *regs = NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
    #ifdef ftrace_regs_set_instruction_pointer
        ftrace_regs_set_instruction_pointer(fregs, ip);
        return;
    #endif
    regs = ftrace_get_regs(fregs);
#else
    regs = fregs->regs;
#endif

    if (regs) {
        #if defined(CONFIG_X86_64) || defined(CONFIG_X86)
            regs->ip = ip;
        #elif defined(CONFIG_ARM64)
            regs->pc = ip;
        #else
            #error Unsupported architecture
        #endif
    }
}

static void notrace fh_ftrace_handler(unsigned long ip, unsigned long parent_ip,
                                      struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

    if (!within_module(parent_ip, THIS_MODULE))
        fh_set_ip(fregs, (unsigned long) hook->function);
}

static int fh_install_hook(struct ftrace_hook *hook)
{
    int err;

    err = fh_resolve_symbol(hook);
    if (err) return err;

    hook->ops.func = fh_ftrace_handler;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
                    | FTRACE_OPS_FL_RECURSION
                    | FTRACE_OPS_FL_IPMODIFY;

    err = _ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
    if (err) {
        pr_err("ftrace_set_filter_ip() failed: %d\n", err);
        return err;
    }

    err = _register_ftrace_function(&hook->ops);
    if (err) {
        pr_err("register_ftrace_function() failed: %d\n", err);
        _ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
        return err;
    }

    return 0;
}

static void fh_remove_hook(struct ftrace_hook *hook)
{
    int err;

    err = _unregister_ftrace_function(&hook->ops);
    if (err) {
        pr_err("unregister_ftrace_function() failed: %d\n", err);
    }

    err = _ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
    if (err) {
        pr_err("ftrace_set_filter_ip() failed: %d\n", err);
    }
}

static int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
    size_t i;
    int err;

    /* First, resolve core ftrace functions */
    err = resolve_ftrace_functions();
    if (err) return err;

    for (i = 0; i < count; i++) {
        err = fh_install_hook(&hooks[i]);
        if (err) goto error;
    }

    return 0;

error:
    while (i != 0) {
        fh_remove_hook(&hooks[--i]);
    }

    return err;
}

static void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
    size_t i;

    for (i = 0; i < count; i++)
        fh_remove_hook(&hooks[i]);
}

#endif