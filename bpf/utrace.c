#include "vmlinux.h"
#include "bpf_helpers.h"

#define PERF_MAX_STACK_DEPTH 127 

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 65536 * 8 * 1024);  // 552MiB
} ringbuf SEC(".maps");

// struct {
//     __uint(type, BPF_MAP_TYPE_ARRAY);
//     __type(key, u32);
//     __type(value, int);
//     __uint(max_entries, 65536);
// } refcnt SEC(".maps");

enum ev_kind {
    EV_KIND_ENTER,
    EV_KIND_EXIT,
};

struct event {
    enum ev_kind kind;
    u32 pid;
    u64 cookie;
    u64 usec;
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
    ev->usec = bpf_ktime_get_boot_ns() / 1000;
    int err = bpf_get_stack(
        ctx,
        ev->stack,
        sizeof(u64) * PERF_MAX_STACK_DEPTH,
        BPF_F_USER_STACK);
    if (err < 0) {
        bpf_printk("get stack failed");
    }

    bpf_ringbuf_submit(ev, 0);

    return 0;
}

SEC("uprobe/generic")
int uprobe_generic(struct pt_regs *ctx) {
    trace_generic(ctx, EV_KIND_ENTER);

    // TODO: handle single insn symbols?
    // u32 key = bpf_get_attach_cookie(ctx);
    // int *cnt = bpf_map_lookup_elem(&refcnt, &key);
    // if (!cnt) {
    //     return 0;
    // }
    //
    // if (*cnt > 0) {
    //     /* An exit event has already been received and dropped.
    //      * This can happen when single insns symbols have the same
    //      * attach point for entry and exit so events can be received in
    //      * any order.
    //      * 
    //      * go tool objdump -s 'main.traceme' /home/matt/misc/traceme/tracee
    //      * TEXT main.traceme(SB) /home/matt/misc/traceme/main.go
    //      * main.go:21		0x4ab320		c3			RET
    //      * 
    //      * nm /home/matt/misc/traceme/tracee |rg traceme
    //      * 00000000004ab320 T main.traceme
    //      *
    //      * Emit another one and add 10 microseconds.
    //      * TODO: mark this event as not precise.
    //      */
    //     bpf_printk("emitting exit event for enter (%d)", *cnt);
    //     trace_generic(ctx, EV_KIND_EXIT);
    //     __sync_fetch_and_add(cnt, -1);
    // }

    return 0;
}

SEC("uretprobe/generic")
int uretprobe_generic(struct pt_regs *ctx) {
    // u32 key = bpf_get_attach_cookie(ctx);
    // int *cnt = bpf_map_lookup_elem(&refcnt, &key);
    // if (!cnt) {
    //     return 0;
    // }
    //
    // if (*cnt <= 0) {
    //     bpf_printk("dropping exit event (%d)", *cnt);
    //     __sync_fetch_and_add(cnt, 1);
    // }

    return trace_generic(ctx, EV_KIND_EXIT);
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
