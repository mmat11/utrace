#include "vmlinux_compact.h"
#include "bpf_helpers.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} ringbuf SEC(".maps");

/*
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 65535);
} calls SEC(".maps");*/

enum ev_kind {
    EV_KIND_ENTRY = 1,
    EV_KIND_EXIT = 2,
};

struct event {
    enum ev_kind kind;
    u64 pid_tgid;
    u64 ts;
    u64 cookie;
    //u32 calls;
} __attribute__((packed));

static void emit_event(enum ev_kind kind, u64 cookie) {
    struct event *ev = bpf_ringbuf_reserve(&ringbuf, sizeof(*ev), 0);
    if (!ev) {
        bpf_printk("ringbuf reserve failed");
        return;
    }

    ev->pid_tgid = bpf_get_current_pid_tgid();
    ev->ts = bpf_ktime_get_ns();
    ev->kind = kind;
    ev->cookie = cookie;

    bpf_ringbuf_submit(ev, 0);
}

SEC("uprobe/generic")
int uprobe_generic(struct pt_regs *ctx) {
    u64 cookie = bpf_get_attach_cookie(ctx);
    emit_event(EV_KIND_ENTRY, cookie);
    return 0;
}

SEC("uretprobe/generic")
int uretprobe_generic(struct pt_regs *ctx) {
    u64 cookie = bpf_get_attach_cookie(ctx);
    emit_event(EV_KIND_EXIT, cookie);
    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
