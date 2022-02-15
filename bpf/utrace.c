#include "vmlinux.h"
#include "bpf_helpers.h"
//#include "bpf_tracing.h"

#define PERF_MAX_STACK_DEPTH 127 

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 65536 * 8 * 1024);  // 552M
} ringbuf SEC(".maps");

enum ev_kind {
    EV_KIND_ENTER,
    EV_KIND_EXIT,
};

struct event {
    enum ev_kind kind;
    u32 pid;
    u64 cookie;
    u64 ns;
    u64 stack[PERF_MAX_STACK_DEPTH];
} __attribute__((packed));

static int trace_generic(struct pt_regs *ctx, enum ev_kind kind) {
    struct event *ev = bpf_ringbuf_reserve(&ringbuf, sizeof(*ev), 0);
    if (!ev) {
        bpf_printk("ringbuf reserve failed");
        return 0;
    }

    ev->kind = kind;
    ev->pid = bpf_get_current_pid_tgid();
    ev->cookie = bpf_get_attach_cookie(ctx);
    ev->ns = bpf_ktime_get_boot_ns();
    int err = bpf_get_stack(
        ctx,
        ev->stack,
        sizeof(u64) * PERF_MAX_STACK_DEPTH,
        BPF_F_USER_STACK);
    if (err < 0) {
        bpf_printk("stack not available");
    }

    bpf_ringbuf_submit(ev, 0);

    return 0;
}

SEC("uprobe/generic")
int uprobe_generic(struct pt_regs *ctx) {
    return trace_generic(ctx, EV_KIND_ENTER);
}

SEC("uretprobe/generic")
int uretprobe_generic(struct pt_regs *ctx) {
    return trace_generic(ctx, EV_KIND_EXIT);
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
