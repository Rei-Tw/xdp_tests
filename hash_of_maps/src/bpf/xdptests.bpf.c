#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct {
        __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
        __type(key, u32);
        __type(value, u32);
        //__uint(pinning, LIBBPF_PIN_BY_NAME);
        __uint(max_entries, 10);
        __uint(map_flags, BPF_F_NO_PREALLOC);
} hmm_prots SEC(".maps");

SEC("xdp")
int xdptests(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	u32 offset = sizeof(struct ethhdr);
	if(data + offset > data_end)
		return XDP_PASS;

	struct iphdr *iph = data + offset;
	offset += sizeof(struct iphdr);
	if (data + offset > data_end)
		return XDP_PASS;

	u16 proto = BPF_CORE_READ(iph, protocol);

	// TCP and UDP
	if(proto != IPPROTO_TCP && proto != IPPROTO_UDP)
		return XDP_DROP;

	/*u32 key = (u32) proto;
	if(bpf_map_lookup_elem(&hmm_prots, &key) != NULL) {
		bpf_printk("Found packet for proto %02x", key);
		return XDP_DROP;
	}*/

	return XDP_PASS;
}

char __license[] SEC("license") = "GPL";