#ifndef SHADOW_H
#define SHADOW_H

#include <linux/ftrace.h>
#include <linux/linkage.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/percpu.h>

/* 
 * 递归保护机制
 * 使用 per-cpu 变量防止同一 CPU 上的无限递归
 */
DECLARE_PER_CPU(int, shadow_recursion_guard);

static inline bool shadow_enter_atomic(void) {
    int *guard = get_cpu_ptr(&shadow_recursion_guard);
    if (*guard) {
        put_cpu_ptr(&shadow_recursion_guard);
        return false;
    }
    *guard = 1;
    return true;
}

static inline void shadow_exit_atomic(void) {
    int *guard = this_cpu_ptr(&shadow_recursion_guard);
    *guard = 0;
    put_cpu_ptr(&shadow_recursion_guard);
}

/* 
 * 兼容性处理：ftrace 递归标志
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
#ifndef FTRACE_OPS_FL_RECURSION
#define FTRACE_OPS_FL_RECURSION FTRACE_OPS_FL_RECURSION_SAFE
#endif
#endif

struct ftrace_hook {
    const char *name;
    void *function;
    void *original;
    unsigned long address;
    struct ftrace_ops ops;
};

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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
static void notrace fh_ftrace_handler(unsigned long ip, unsigned long parent_ip,
                                      struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
    struct pt_regs *regs = ftrace_get_regs(fregs);
    if (!within_module(parent_ip, THIS_MODULE) && regs) {
#if defined(CONFIG_X86_64) || defined(CONFIG_X86)
        regs->ip = (unsigned long) hook->function;
#elif defined(CONFIG_ARM64)
        regs->pc = (unsigned long) hook->function;
#endif
    }
}
#else
static void notrace fh_ftrace_handler(unsigned long ip, unsigned long parent_ip,
                                      struct ftrace_ops *ops, struct pt_regs *regs)
{
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
    if (!within_module(parent_ip, THIS_MODULE) && regs) {
#if defined(CONFIG_X86_64) || defined(CONFIG_X86)
        regs->ip = (unsigned long) hook->function;
#elif defined(CONFIG_ARM64)
        regs->pc = (unsigned long) hook->function;
#endif
    }
}
#endif

#endif