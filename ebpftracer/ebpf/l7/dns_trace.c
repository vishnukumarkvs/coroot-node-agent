// DNS-only tracing.
//
// This is a lean alternative to the full L7 pipeline: it hooks only
// sys_enter_sendto / sys_enter_recvfrom / sys_exit_recvfrom, filters on
// UDP destination/source port 53, and emits small DNS events into the
// existing `l7_events` perf buffer (reusing `struct l7_event` and the
// `l7_event_heap` per-CPU array), so the userspace decoder and the
// onDNSRequest path work unchanged.
//
// These programs are mutually exclusive with the full L7 syscall
// tracepoints: the Go side attaches either the L7 programs or these
// `dns_*` programs, never both.
//
// NOTE: the tracepoint section names must NOT collide with the L7 ones
// (each ELF section name must be unique), which is why they carry the
// `dns_` prefix. At runtime the Go code skips them in the generic attach
// loop and attaches them to the real tracepoints manually.

#define DNS_PORT 53

struct dns_sys_enter_args {
    __u64 unused;
    __u64 unused2;
    __u64 fd;
    char* buf;
    __u64 size;   // len
    __u64 flags;
    __u64 addr;   // struct sockaddr* (userspace pointer)
    __u64 addr_len;
};

// Key of a pending DNS request, matched by the raw (unconverted) header
// transaction ID which is echoed verbatim in the response.
struct dns_req_key {
    __u64 fd;
    __u32 pid;
    __u16 stream_id;
    __u16 pad;
};

// A DNS request captured on sys_enter_sendto, pending a response.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(struct dns_req_key));
    __uint(value_size, sizeof(__u64)); // request timestamp (ns)
    __uint(max_entries, 10240);
} active_dns_requests SEC(".maps");

// recvfrom arguments captured on sys_enter, replayed on sys_exit (the
// sys_exit tracepoint only carries the return value).
struct dns_recvfrom_args {
    __u64 fd;
    char* buf;
    __u64 addr;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(__u64)); // tid
    __uint(value_size, sizeof(struct dns_recvfrom_args));
    __uint(max_entries, 10240);
} dns_reads SEC(".maps");

// Reads the sa_family + sa_port of a sockaddr. Both sockaddr_in and
// sockaddr_in6 place the family at offset 0 and the port at offset 2.
struct dns_sockaddr {
    __u16 sa_family;
    __u16 sa_port;
};

static __always_inline
int dns_dest_port_is_53(__u64 addr) {
    if (addr == 0) {
        return 0;
    }
    struct dns_sockaddr sa = {};
    if (bpf_probe_read(&sa, sizeof(sa), (void*)addr)) {
        return 0;
    }
    return bpf_ntohs(sa.sa_port) == DNS_PORT;
}

SEC("tracepoint/syscalls/dns_sys_enter_sendto")
int dns_sys_enter_sendto(struct dns_sys_enter_args* ctx) {
    if (!dns_dest_port_is_53(ctx->addr)) {
        return 0;
    }
    __s16 stream_id = 0;
    if (!is_dns_request(ctx->buf, ctx->size, &stream_id)) {
        return 0;
    }
    __u64 id = bpf_get_current_pid_tgid();
    struct dns_req_key k = {};
    k.fd = ctx->fd;
    k.pid = id >> 32;
    k.stream_id = (__u16)stream_id;
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&active_dns_requests, &k, &ts, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/dns_sys_enter_recvfrom")
int dns_sys_enter_recvfrom(struct dns_sys_enter_args* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct dns_recvfrom_args args = {};
    args.fd = ctx->fd;
    args.buf = ctx->buf;
    args.addr = ctx->addr;
    bpf_map_update_elem(&dns_reads, &id, &args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/dns_sys_exit_recvfrom")
int dns_sys_exit_recvfrom(struct trace_event_raw_sys_exit__stub* ctx) {
    if (ctx->ret <= 0) {
        return 0;
    }
    __u64 id = bpf_get_current_pid_tgid();
    struct dns_recvfrom_args* args = bpf_map_lookup_elem(&dns_reads, &id);
    if (!args) {
        return 0;
    }
    bpf_map_delete_elem(&dns_reads, &id);
    if (args->buf == 0) {
        return 0;
    }
    if (!dns_dest_port_is_53(args->addr)) {
        return 0;
    }
    __s16 stream_id = 0;
    __s32 status = 0;
    if (!is_dns_response(args->buf, (__u64)ctx->ret, &stream_id, &status)) {
        return 0;
    }
    struct dns_req_key k = {};
    k.fd = args->fd;
    k.pid = id >> 32;
    k.stream_id = (__u16)stream_id;
    __u64* ts = bpf_map_lookup_elem(&active_dns_requests, &k);
    if (!ts) {
        return 0;
    }
    __u32 zero = 0;
    struct l7_event* e = bpf_map_lookup_elem(&l7_event_heap, &zero);
    if (!e) {
        return 0;
    }
    e->fd = args->fd;
    e->connection_timestamp = 0;
    e->pid = id >> 32;
    e->status = status;
    e->duration = bpf_ktime_get_ns() - *ts;
    e->protocol = PROTOCOL_DNS;
    e->method = 0;
    e->is_inbound = 0;
    e->padding = 0;
    e->statement_id = 0;
    __u64 payload_size = (__u64)ctx->ret;
    TRUNCATE_PAYLOAD_SIZE(payload_size);
    if (bpf_probe_read(e->payload, payload_size, (void*)args->buf)) {
        payload_size = 0;
    }
    e->payload_size = payload_size;
    bpf_perf_event_output(ctx, &l7_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
    bpf_map_delete_elem(&active_dns_requests, &k);
    return 0;
}