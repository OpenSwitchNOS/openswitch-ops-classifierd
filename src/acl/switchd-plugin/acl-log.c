/* Copyright (C) 2016 Hewlett Packard Enterprise Development LP
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>
#include <vswitch-idl.h>
//#include <ovsdb-idl.h>
//#include <openswitch-idl.h>
#include <smap.h>

#include <stdint.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/mpls.h>

#include "acl-log.h"
#include "acl_parse.h"
#include "connectivity.h"
#include "ovs-thread.h"
#include "packets.h"
#include "poll-loop.h"
#include "run-blocks.h"
#include "seq.h"
#include "timer.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ops_cls_acl_log);

/* These are for the interaction between PI and PD */
static struct seq *acl_log_pktrx_seq;
static struct ovs_mutex acl_log_mutex = OVS_MUTEX_INITIALIZER;
static struct acl_log_info info OVS_GUARDED_BY(acl_log_mutex) = { .valid_fields = 0 };

/* These are for the switchd plugins */
static uint64_t acllog_seqno = LLONG_MIN;
static struct timer my_timer, start_timer;
static int my_timer_interval = 30 * 1000;

/* Provides a global seq for acl logging events.
 *
 * ACL logging modules should call seq_change() on the returned object whenever
 * a packet is received for ACL logging.
 *
 * Clients can seq_wait() on this object to do the logging and tell all ASICs
 * to stop copying packets to the CPU. */
struct seq *
acl_log_pktrx_seq_get(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    if (ovsthread_once_start(&once)) {
        acl_log_pktrx_seq = seq_create();
        ovsthread_once_done(&once);
    }

    return acl_log_pktrx_seq;
}

void
acl_log_pkt_data_get(struct acl_log_info *pkt_info_to_get)
{
   /* validate the input */
   if (!pkt_info_to_get)
      return;

   /* take the mutex */
   ovs_mutex_lock(&acl_log_mutex);

   /* copy the static value into the data to be returned */
   memcpy(pkt_info_to_get, &info, sizeof(struct acl_log_info));

   /* zero out the static value to avoid returning the same packet info twice*/
   memset(&info, 0, sizeof(struct acl_log_info));

   /* give the mutex */
   ovs_mutex_unlock(&acl_log_mutex);
}

void
acl_log_pkt_data_set(struct acl_log_info *new_pkt)
{
   /* validate the input */
   if (!new_pkt) {
      VLOG_ERR("PD Called PI Successfully in %s", __func__);
      return;
   }

   /* take the mutex */
   ovs_mutex_lock(&acl_log_mutex);

   /* copy the argument into the static value */
   memcpy(&info, new_pkt, sizeof(struct acl_log_info));

   /* give the mutex */
   ovs_mutex_unlock(&acl_log_mutex);

   /* Call seq_change */
   seq_change(acl_log_pktrx_seq_get());
}






static inline uint8_t *skb_network_header(struct sk_buff *skb)
{
    return skb->head + skb->network_header;
}

static inline int skb_network_offset(struct sk_buff *skb)
{
    return skb_network_header(skb) - skb->data;
}

static inline struct iphdr *ip_hdr(struct sk_buff *skb)
{
    return (struct iphdr *)skb_network_header(skb);
}

static inline uint8_t *skb_transport_header(const struct sk_buff *skb)
{
    return skb->head + skb->transport_header;
}

static inline struct ipv6hdr *ipv6_hdr(struct sk_buff *skb)
{
    return (struct ipv6hdr *)skb_network_header(skb);
}

static inline uint16_t vlan_get_tci(struct sk_buff *skb)
{
    return skb->vlan_tci;
}

static inline void skb_reset_transport_header(struct sk_buff *skb)
{
    skb->transport_header = skb->data - skb->head;
}

static inline void skb_set_transport_header(struct sk_buff *skb, int offset)
{
    skb_reset_transport_header(skb);
    skb->transport_header += offset;
}

static inline int skb_transport_offset(struct sk_buff *skb)
{
    return skb_transport_header(skb) - skb->data;
}

static inline unsigned int ip_hdrlen(struct sk_buff *skb)
{
    return ip_hdr(skb)->ihl * 4;
}

static inline unsigned int skb_headlen(const struct sk_buff *skb)
{
    return skb->len - skb->data_len;
}

static inline void skb_reset_mac_header(struct sk_buff *skb)
{
    skb->mac_header = skb->data - skb->head;
}

static inline unsigned char *skb_mac_header(const struct sk_buff *skb)
{
    return skb->head + skb->mac_header;
}

static inline void skb_reset_mac_len(struct sk_buff *skb)
{
    skb->mac_len = skb->network_header - skb->mac_header;
}

static inline void skb_reset_network_header(struct sk_buff *skb)
{
    skb->network_header = skb->data - skb->head;
}

static inline void skb_set_network_header(struct sk_buff *skb, const int offset)
{
    skb_reset_network_header(skb);
    skb->network_header += offset;
}

static inline void ether_addr_copy(uint8_t *dst, const uint8_t *src)
{
    uint16_t *a = (uint16_t *)dst;
    const uint16_t *b = (const uint16_t *)src;

    a[0] = b[0];
    a[1] = b[1];
    a[2] = b[2];
}

static inline struct ethhdr *eth_hdr(const struct sk_buff *skb)
{
    return (struct ethhdr *)skb_mac_header(skb);
}

static inline struct tcphdr *tcp_hdr(const struct sk_buff *skb)
{
    return (struct tcphdr *)skb_transport_header(skb);
}

static inline struct udphdr *udp_hdr(const struct sk_buff *skb)
{
    return (struct udphdr *)skb_transport_header(skb);
}

static inline struct sctphdr *sctp_hdr(const struct sk_buff *skb)
{
    return (struct sctphdr *)skb_transport_header(skb);
}

static inline struct icmphdr *icmp_hdr(const struct sk_buff *skb)
{
    return (struct icmphdr *)skb_transport_header(skb);
}

static inline int pskb_may_pull(struct sk_buff *skb, unsigned int len)
{
    if (len <= skb_headlen(skb))
        return 1;
    else
        return 0;
}

static inline int check_header(struct sk_buff *skb, int len)
{
    if (skb->len < len)
        return -EINVAL;
    if (!pskb_may_pull(skb, len))
        return -ENOMEM;
    return 0;
}

static inline bool arphdr_ok(struct sk_buff *skb)
{
    return pskb_may_pull(skb, skb_network_offset(skb) +
            sizeof(struct arp_eth_header));
}

static inline int check_iphdr(struct sk_buff *skb)
{
    unsigned int nh_ofs = skb_network_offset(skb);
    unsigned int ip_len;
    int err;

    err = check_header(skb, nh_ofs + sizeof(struct iphdr));
    if (err)
        return err;

    ip_len = ip_hdrlen(skb);
    if (ip_len < sizeof(struct iphdr) ||
            skb->len < nh_ofs + ip_len)
        return -EINVAL;

    skb_set_transport_header(skb, nh_ofs + ip_len);
    return 0;
}

static inline bool tcphdr_ok(struct sk_buff *skb)
{
    int th_ofs = skb_transport_offset(skb);

    if (!pskb_may_pull(skb, th_ofs + sizeof(struct tcphdr)))
        return false;

    return true;
}

static inline bool udphdr_ok(struct sk_buff *skb)
{
    return pskb_may_pull(skb, skb_transport_offset(skb) +
            sizeof(struct udphdr));
}

static inline bool icmphdr_ok(struct sk_buff *skb)
{
    return pskb_may_pull(skb, skb_transport_offset(skb) +
            sizeof(struct icmphdr));
}

static inline uint8_t *__skb_push(struct sk_buff *skb, unsigned int len)
{
    skb->data -= len;
    skb->len  += len;
    return skb->data;
}

static inline uint8_t *__skb_pull(struct sk_buff *skb, unsigned int len)
{
    skb->len -= len;
    if (skb->len < skb->data_len)
    {
        //VLOG_ERR("Trying to move pointer beyond the end of buffer");
        exit(1);
    }
    return skb->data += len;
}

static inline bool eth_p_mpls(uint16_t eth_type)
{
    return eth_type == htons(ETH_P_MPLS_UC) ||
        eth_type == htons(ETH_P_MPLS_MC);
}

#define ARPHRD_ETHER            1
#define NEXTHDR_TCP             6       /* TCP segment. */
#define NEXTHDR_UDP             17      /* UDP message. */
#define NEXTHDR_ICMP            58      /* ICMP for IPv6. */
#define NEXTHDR_NONE            59      /* No next header */
#define NEXTHDR_SCTP            132     /* SCTP message. */
#define VLAN_TAG_PRESENT        0x1000

static inline int parse_vlan(struct sk_buff *skb, struct pkt_info *key)
{
    struct qtag_prefix {
        uint16_t eth_type; /* ETH_P_8021Q */
        uint16_t tci;
    };
    struct qtag_prefix *qp;

    if (skb->len < sizeof(struct qtag_prefix) + sizeof(uint16_t))
        return 0;

    if (!pskb_may_pull(skb, sizeof(struct qtag_prefix) +
                sizeof(uint16_t)))
        return -ENOMEM;

    qp = (struct qtag_prefix *) skb->data;
    key->eth.tci = qp->tci | htons(VLAN_TAG_PRESENT);
    __skb_pull(skb, sizeof(struct qtag_prefix));

    return 0;
}

static inline uint16_t skb_vlan_tag_present(struct sk_buff *skb)
{
    return ((skb)->vlan_tci & VLAN_TAG_PRESENT);
}

#define LLC_SAP_SNAP 0xAA
#define ETH_P_802_3_MIN 0x0600
static inline uint16_t parse_ethertype(struct sk_buff *skb)
{
    struct llc_snap_hdr {
        uint8_t  dsap;  /* Always 0xAA */
        uint8_t  ssap;  /* Always 0xAA */
        uint8_t  ctrl;
        uint8_t  oui[3];
        uint16_t ethertype;
    };
    struct llc_snap_hdr *llc;
    uint16_t proto;

    proto = *(uint16_t *) skb->data;
    __skb_pull(skb, sizeof(uint16_t));

    proto &= htons(0xFF00);
    if (proto >= htons(ETH_P_802_3_MIN))
        return proto;

    if (skb->len < sizeof(struct llc_snap_hdr))
        return htons(ETH_P_802_2);

    if (!pskb_may_pull(skb, sizeof(struct llc_snap_hdr)))
        return htons(0);

    llc = (struct llc_snap_hdr *) skb->data;
    if (llc->dsap != LLC_SAP_SNAP ||
            llc->ssap != LLC_SAP_SNAP ||
            (llc->oui[0] | llc->oui[1] | llc->oui[2]) != 0)
        return htons(ETH_P_802_2);

    __skb_pull(skb, sizeof(struct llc_snap_hdr));

    llc->ethertype &= htons(0xFF00);
    if (llc->ethertype >= htons(ETH_P_802_3_MIN))
        return llc->ethertype;

    return htons(ETH_P_802_2);
}


void
acl_log_init(struct run_blk_params *blk_params)
{
      acllog_seqno = seq_read(acl_log_pktrx_seq_get());
      VLOG_INFO("ACL LOG INIT");
}

void
acl_log_run(struct run_blk_params *blk_params)
{
    uint64_t seq;
    uint32_t timer_secs = atoi(ACL_LOG_TIMER_DEFAULT);
    long long int cur_time = time_msec();
    const char *timer_interval_str;
    const struct ovsrec_system *ovs;

    seq = seq_read(acl_log_pktrx_seq_get());

    timer_secs = 30; /* temporary hard code - will get from db */

    /* Get the timer interval from the System table */
    ovs = ovsrec_system_first(blk_params->idl);
    if (ovs) {
        timer_interval_str = smap_get(&ovs->other_config, ACL_LOG_TIMER_STR);
        if (timer_interval_str) {
            timer_secs = atoi(timer_interval_str);
            VLOG_DBG("ACL log timer interval is %d", timer_secs);
        } else {
            VLOG_INFO("ACL log timer interval not found");
        }
    } else {
        VLOG_WARN("Unable to read from database");
    }

    if ((!timer_is_infinite(&start_timer)) ||
            (start_timer.t + (timer_secs * 1000) > cur_time)) {
        /* if we are within the timer interval, ignore any packets that were
         * received */
        if (seq != acllog_seqno) {
            acllog_seqno = seq;
        }
    } else if (seq != acllog_seqno)
    {
        /* check to see if a packet was received for logging */
        struct pkt_info key;
        struct sk_buff pkt_buff;
        int ace_seq_no;
        char msg[128] = { 0 };
        int msg_len = sizeof(msg);
        int msg_used = 0;

        memset(&key, 0, sizeof(key));
        memset(&pkt_buff, 0, sizeof(pkt_buff));
        acllog_seqno = seq;

        /* stop the system from capturing any more packets */
        /*     functionality currently unavailable */

        /* get the packet info */
        acl_log_pkt_data_get(&pkt_buff.pkt_info);
        pkt_buff.head = pkt_buff.pkt_info.pkt_data;
        pkt_buff.data = pkt_buff.head;
        pkt_buff.len = pkt_buff.pkt_info.pkt_buffer_len;

        /* parse and log the packet */
        key_extract(&pkt_buff, &key);

        /* fill in unknown data about the ACL/ACE */
        if (!(ACL_LOG_ENTRY_NUM & pkt_buff.pkt_info.valid_fields)) {
            /* dummy for now */
            pkt_buff.pkt_info.entry_num = 0; /* change me later */
        }
        /* needs to be properly converted */
        ace_seq_no = pkt_buff.pkt_info.entry_num;
        if (!(ACL_LOG_LIST_NAME & pkt_buff.pkt_info.valid_fields)) {
            /* dummy for now */
            snprintf(pkt_buff.pkt_info.list_name,
                    sizeof(pkt_buff.pkt_info.list_name),
                    "Unavailable"); /* change me later */
        }

        msg_used = snprintf(msg, msg_len, "List %s, seq#%d %s %s ",
                pkt_buff.pkt_info.list_name,
                ace_seq_no,
                "denied", /* only deny logging is currently supported */
                acl_parse_protocol_get_name_from_number(key.ip.proto));
        if (msg_used < msg_len) {
            msg_used += snprintf(msg + msg_used, msg_len - msg_used,
                    "%d.%d.%d.%d",
                    (key.ipv4.addr.src >> 24) & 0xff,
                    (key.ipv4.addr.src >> 16) & 0xff,
                    (key.ipv4.addr.src >> 8) & 0xff,
                    key.ipv4.addr.src & 0xff
                    );
        }
        if ((msg_used < msg_len) &&
                ((key.ip.proto == IPPROTO_UDP) || (key.ip.proto == IPPROTO_TCP))) {
            msg_used += snprintf(msg + msg_used, msg_len - msg_used,
                    "(%d)", key.tp.src);
        }
        if (msg_used < msg_len) {
            msg_used += snprintf(msg + msg_used, msg_len - msg_used,
                    " -> %d.%d.%d.%d",
                    (key.ipv4.addr.dst >> 24) & 0xff,
                    (key.ipv4.addr.dst >> 16) & 0xff,
                    (key.ipv4.addr.dst >> 8) & 0xff,
                    key.ipv4.addr.dst & 0xff
                    );
        }
        if (msg_used < msg_len) {
            if ((key.ip.proto == IPPROTO_UDP) || (key.ip.proto == IPPROTO_TCP)) {
                msg_used += snprintf(msg + msg_used, msg_len - msg_used,
                        "(%d) ", key.tp.dst);
            } else if (key.ip.proto == IPPROTO_ICMP) {
                msg_used += snprintf(msg + msg_used, msg_len - msg_used,
                        " type %d code %d, ", key.tp.src, key.tp.dst);
            }
        }
        if (msg_used < msg_len) {
            msg_used += snprintf(msg + msg_used, msg_len - msg_used,
                    "on vlan %d, port %d",
                    pkt_buff.pkt_info.ingress_vlan,
                    pkt_buff.pkt_info.ingress_port);
        }
        VLOG_INFO("%s", msg);

        if (timer_is_infinite(&start_timer))
        {
            /* this is the first time receiving a packet, so the ACEs may have
             * non-zero counts that we have not previously stored */
            /* TODO: reset statistics */
        }
        /* indicate to the wait function to 'set' the timer */
        timer_set_expired(&start_timer);
    }
    else if (start_timer.t + (timer_secs * 1000) <= cur_time) {
        /* the timer has expired */
        VLOG_DBG("ACL log timer expired");

        /* TODO */
        /* 1. get the statistics for ACEs with the log action */
        /* 2. print diffs */
        /* 3. update previous counts */

        /* start receiving packets again */
        timer_set_expired(&start_timer);
    }
}

void
acl_log_wait(struct run_blk_params *blk_params)
{
    // need to update poll_timer_wait_until if it has changed.
    //if ()
    if (!(timer_expired(&my_timer) || timer_is_infinite(&my_timer)))
    {
        timer_set_duration(&my_timer, my_timer_interval);
        poll_timer_wait_until(my_timer.t);
        VLOG_INFO("ACL LOG TIMER reset");
    }
    seq_wait(acl_log_pktrx_seq_get(), acllog_seqno);
}

/**
 * key_extract - extracts a flow key from an Ethernet frame.
 * @skb: sk_buff that contains the frame, with skb->data pointing to the
 * Ethernet header
 * @key: output flow key
 *
 * The caller must ensure that skb->len >= ETH_HLEN.
 *
 * Returns 0 if successful, otherwise a negative errno value.
 *
 * Initializes @skb header pointers as follows:
 *
 *    - skb->mac_header: the Ethernet header.
 *
 *    - skb->network_header: just past the Ethernet header, or just past the
 *      VLAN header, to the first byte of the Ethernet payload.
 *
 *    - skb->transport_header: If key->eth.type is ETH_P_IP or ETH_P_IPV6
 *      on output, then just past the IP header, if one is present and
 *      of a correct length, otherwise the same as skb->network_header.
 *      For other key->eth.type values it is left untouched.
 */
int key_extract(struct sk_buff *skb, struct pkt_info *key)
{
   int error;
   struct ethhdr *eth;

   /* Flags are always used as part of stats */
   key->tp.flags = 0;

   skb_reset_mac_header(skb);

   /* Link layer.  We are guaranteed to have at least the 14 byte Ethernet
    * header in the linear data area.
    */
   eth = eth_hdr(skb);
   ether_addr_copy(key->eth.src, eth->h_source);
   ether_addr_copy(key->eth.dst, eth->h_dest);

   __skb_pull(skb, 2 * ETH_ALEN);
   /* We are going to push all headers that we pull, so no need to
    * update skb->csum here.
    */

   key->eth.tci = 0;
   if (skb_vlan_tag_present(skb))
      key->eth.tci = htons(vlan_get_tci(skb));
   else if (eth->h_proto == htons(ETH_P_8021Q))
      if (parse_vlan(skb, key))
         return -ENOMEM;

   key->eth.type = parse_ethertype(skb);
   if (key->eth.type == htons(0))
      return -ENOMEM;

   skb_reset_network_header(skb);
   skb_reset_mac_len(skb);
   __skb_push(skb, skb->data - skb_mac_header(skb));

   /* Network layer. */
   if (key->eth.type == htons(ETH_P_IP)) {
      struct iphdr *nh;

      error = check_iphdr(skb);
      if (error) {
         memset(&key->ip, 0, sizeof(key->ip));
         memset(&key->ipv4, 0, sizeof(key->ipv4));
         if (error == -EINVAL) {
            skb->transport_header = skb->network_header;
            error = 0;
         }
         return error;
      }

      nh = ip_hdr(skb);
      key->ipv4.addr.src = htonl(nh->saddr);
      key->ipv4.addr.dst = htonl(nh->daddr);

      key->ip.proto = nh->protocol;
      key->ip.tos = nh->tos;
      key->ip.ttl = nh->ttl;

      /* Transport layer. */
      if (key->ip.proto == IPPROTO_TCP) {
         if (tcphdr_ok(skb)) {
            struct tcphdr *tcp = tcp_hdr(skb);
            key->tp.src = htons(tcp->source);
            key->tp.dst = htons(tcp->dest);
            key->tp.flags = TCP_FLAGS_BE16(*(uint16_t *)&(((union tcp_word_hdr *)(tcp))->words[3]));
         } else {
            memset(&key->tp, 0, sizeof(key->tp));
         }

      } else if (key->ip.proto == IPPROTO_UDP) {
         if (udphdr_ok(skb)) {
            struct udphdr *udp = udp_hdr(skb);
            key->tp.src = htons(udp->source);
            key->tp.dst = htons(udp->dest);
         } else {
            memset(&key->tp, 0, sizeof(key->tp));
         }
      } else if (key->ip.proto == IPPROTO_ICMP) {
         if (icmphdr_ok(skb)) {
            struct icmphdr *icmp = icmp_hdr(skb);
            /* The ICMP type and code fields use the 16-bit
             * transport port fields, so we need to store
             * them in 16-bit network byte order.
             */
            key->tp.src = htons(icmp->type);
            key->tp.dst = htons(icmp->code);
         } else {
            memset(&key->tp, 0, sizeof(key->tp));
         }
      }

   } else if (key->eth.type == htons(ETH_P_ARP) ||
         key->eth.type == htons(ETH_P_RARP)) {
      struct arp_eth_header *arp;
      bool arp_available = arphdr_ok(skb);

      arp = (struct arp_eth_header *)skb_network_header(skb);

      if (arp_available &&
            arp->ar_hrd == htons(ARPHRD_ETHER) &&
            arp->ar_pro == htons(ETH_P_IP) &&
            arp->ar_hln == ETH_ALEN &&
            arp->ar_pln == 4) {

         /* We only match on the lower 8 bits of the opcode. */
         if (ntohs(arp->ar_op) <= 0xff)
            key->ip.proto = ntohs(arp->ar_op);
         else
            key->ip.proto = 0;

         memcpy((uint8_t *)(((uint8_t *)&key->ipv4.addr.src) + 2), &arp->ar_spa.hi, sizeof(uint16_t));
         memcpy(&key->ipv4.addr.src, &arp->ar_spa.lo, sizeof(uint16_t));
         memcpy((uint8_t *)(((uint8_t *)&key->ipv4.addr.dst) + 2), &arp->ar_tpa.hi, sizeof(uint16_t));
         memcpy(&key->ipv4.addr.dst, &arp->ar_tpa.lo, sizeof(uint16_t));
         ether_addr_copy(key->ipv4.arp.sha, arp->ar_sha.ea);
         ether_addr_copy(key->ipv4.arp.tha, arp->ar_tha.ea);
      } else {
         memset(&key->ip, 0, sizeof(key->ip));
         memset(&key->ipv4, 0, sizeof(key->ipv4));
      }
   } else if (eth_p_mpls(key->eth.type)) {
      size_t stack_len = MPLS_HLEN;

      /* In the presence of an MPLS label stack the end of the L2
       * header and the beginning of the L3 header differ.
       *
       * Advance network_header to the beginning of the L3
       * header. mac_len corresponds to the end of the L2 header.
       */
      while (1) {
         uint32_t lse;

         error = check_header(skb, skb->mac_len + stack_len);
         if (error)
            return 0;

         memcpy(&lse, skb_network_header(skb), MPLS_HLEN);

         if (stack_len == MPLS_HLEN)
            memcpy(&key->mpls.top_lse, &lse, MPLS_HLEN);

         skb_set_network_header(skb, skb->mac_len + stack_len);
         if (lse & htonl(MPLS_LS_S_MASK))
            break;

         stack_len += MPLS_HLEN;
      }
   } else if (key->eth.type == htons(ETH_P_IPV6)) {
      return 0;
//      int nh_len;             /* IPv6 Header + Extensions */
//
//      nh_len = parse_ipv6hdr(skb, key);
//      if (nh_len < 0) {
//         memset(&key->ip, 0, sizeof(key->ip));
//         memset(&key->ipv6.addr, 0, sizeof(key->ipv6.addr));
//         if (nh_len == -EINVAL) {
//            skb->transport_header = skb->network_header;
//            error = 0;
//         } else {
//            error = nh_len;
//         }
//         return error;
//      }

      /* Transport layer. */
      if (key->ip.proto == NEXTHDR_TCP) {
         if (tcphdr_ok(skb)) {
            struct tcphdr *tcp = tcp_hdr(skb);
            key->tp.src = htons(tcp->source);
            key->tp.dst = htons(tcp->dest);
            key->tp.flags = TCP_FLAGS_BE16(*(uint16_t *)&(((union tcp_word_hdr *)(tcp))->words[3]));
         } else {
            memset(&key->tp, 0, sizeof(key->tp));
         }
      } else if (key->ip.proto == NEXTHDR_UDP) {
         if (udphdr_ok(skb)) {
            struct udphdr *udp = udp_hdr(skb);
            key->tp.src = htons(udp->source);
            key->tp.dst = htons(udp->dest);
         } else {
            memset(&key->tp, 0, sizeof(key->tp));
         }
      } else if (key->ip.proto == NEXTHDR_ICMP) {
//         if (icmp6hdr_ok(skb)) {
//            error = parse_icmpv6(skb, key, nh_len);
//            if (error)
               return error;
//         } else {
//            memset(&key->tp, 0, sizeof(key->tp));
//         }
      }
   }
   return 0;
}
