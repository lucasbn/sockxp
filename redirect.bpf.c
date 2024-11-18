#include <linux/bpf.h>
#include <sys/socket.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define LOCALHOST_IPV4 16777343

struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(max_entries, 2);
    __type(key, int);
    __type(value, int);
} sock_map SEC(".maps");

char _license[] SEC("license") = "GPL";

SEC("sk_msg")
int sk_msg_prog(struct sk_msg_md *msg)
{   
    if(msg->remote_ip4 != LOCALHOST_IPV4 || msg->local_ip4!= LOCALHOST_IPV4)
        return SK_PASS;

    int key;
    if (bpf_htonl(msg->remote_port) == 3000) {
        key = 1;
    } else {
        key = 0;
    }

    return bpf_msg_redirect_map(msg, &sock_map, key, BPF_F_INGRESS);
}

SEC("sockops")
int sockops_prog(struct bpf_sock_ops *skops){

    __u32 op = skops->op;
    if (op != BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB
    && op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) {
        return BPF_OK;
    }

    if(skops->remote_ip4 != LOCALHOST_IPV4 || skops->local_ip4!= LOCALHOST_IPV4) {
        return BPF_OK;
    }

    if (!skops->sk)
        return SK_PASS;

    switch (skops->op) {
        case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
            if (bpf_sock_map_update(skops, &sock_map, &(__u32){ 0 }, BPF_ANY) != 0) {
                bpf_printk("Failed to update active mapping\n");
            }
            break;
        case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
            if (bpf_sock_map_update(skops, &sock_map, &(__u32){ 1 }, BPF_ANY) != 0) {
                bpf_printk("Failed to update passive mapping\n");
            }
            break;
    }

    return BPF_OK;
}
