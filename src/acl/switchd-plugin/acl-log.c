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
#include <smap.h>
#include <dynamic-string.h>

#include <stdint.h>
#include <errno.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/mpls.h>
#include <linux/llc.h>

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
static long long int start_time = LLONG_MIN;
static int32_t prev_timer_interval_ms = 0;

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

/* Packet parsing code */

struct pkt_info {
    struct {
        uint8_t     src[ETH_ALEN];	/**< Ethernet source address. */
        uint8_t     dst[ETH_ALEN];	/**< Ethernet destination address. */
        uint16_t tci;		/**< 0 if no VLAN, VLAN_TAG_PRESENT set otherwise. */
        uint16_t type;		/**< Ethernet frame type. */
    } eth;
    union {
        struct {
            uint32_t top_lse;	/**< top label stack entry */
        } mpls;
        struct {
            uint8_t     proto;	/**< IP protocol or lower 8 bits of ARP opcode. */
            uint8_t     tos;	    /**< IP ToS. */
            uint8_t     ttl;	    /**< IP TTL/hop limit. */
            uint8_t     frag;	/**< One of OVS_FRAG_TYPE_*. */
        } ip;
    };
    struct {
        uint16_t src;		/**< TCP/UDP/SCTP source port. */
        uint16_t dst;		/**< TCP/UDP/SCTP destination port. */
        uint16_t flags;		/**< TCP flags. */
    } tp;
    union {
        struct {
            struct {
                uint32_t src;	/**< IP source address. */
                uint32_t dst;	/**< IP destination address. */
            } addr;
            struct {
                uint8_t sha[ETH_ALEN];	/**< ARP source hardware address. */
                uint8_t tha[ETH_ALEN];	/**< ARP target hardware address. */
            } arp;
        } ipv4;
        struct {
            struct {
                struct in6_addr src;	/**< IPv6 source address. */
                struct in6_addr dst;	/**< IPv6 destination address. */
            } addr;
            uint32_t label;			/**< IPv6 flow label. */
            struct {
                struct in6_addr target;	/**< ND target address. */
                uint8_t sll[ETH_ALEN];	/**< ND source link layer address. */
                uint8_t tll[ETH_ALEN];	/**< ND target link layer address. */
            } nd;
        } ipv6;
    };
};

struct parse_buff {
    struct acl_log_info pkt_info;
    unsigned int len;
    unsigned int data_len;
    uint16_t mac_len;
    uint16_t hdr_len;
    uint16_t vlan_tci;
    uint8_t transport_header;
    uint8_t network_header;
    uint8_t mac_header;
    uint8_t *data;
    uint8_t *head;
};

static inline uint8_t *pab_network_header(struct parse_buff *pab)
{
    return pab->head + pab->network_header;
}

static inline int pab_network_offset(struct parse_buff *pab)
{
    return pab_network_header(pab) - pab->data;
}

static inline struct iphdr *ip_hdr(struct parse_buff *pab)
{
    return (struct iphdr *)pab_network_header(pab);
}

static inline uint8_t *pab_transport_header(const struct parse_buff *pab)
{
    return pab->head + pab->transport_header;
}

static inline struct ipv6hdr *ipv6_hdr(struct parse_buff *pab)
{
    return (struct ipv6hdr *)pab_network_header(pab);
}

static inline uint16_t vlan_get_tci(struct parse_buff *pab)
{
    return pab->vlan_tci;
}

static inline void pab_reset_transport_header(struct parse_buff *pab)
{
    pab->transport_header = pab->data - pab->head;
}

static inline void pab_set_transport_header(struct parse_buff *pab, int offset)
{
    pab_reset_transport_header(pab);
    pab->transport_header += offset;
}

static inline int pab_transport_offset(struct parse_buff *pab)
{
    return pab_transport_header(pab) - pab->data;
}

static inline unsigned int ip_hdrlen(struct parse_buff *pab)
{
    return ip_hdr(pab)->ihl * 4;
}

static inline unsigned int pab_headlen(const struct parse_buff *pab)
{
    return pab->len - pab->data_len;
}

static inline void pab_reset_mac_header(struct parse_buff *pab)
{
    pab->mac_header = pab->data - pab->head;
}

static inline unsigned char *pab_mac_header(const struct parse_buff *pab)
{
    return pab->head + pab->mac_header;
}

static inline void pab_reset_mac_len(struct parse_buff *pab)
{
    pab->mac_len = pab->network_header - pab->mac_header;
}

static inline void pab_reset_network_header(struct parse_buff *pab)
{
    pab->network_header = pab->data - pab->head;
}

static inline void pab_set_network_header(struct parse_buff *pab, const int offset)
{
    pab_reset_network_header(pab);
    pab->network_header += offset;
}

static inline void ether_addr_copy(uint8_t *dst, const uint8_t *src)
{
    uint16_t *a = (uint16_t *)dst;
    const uint16_t *b = (const uint16_t *)src;

    a[0] = b[0];
    a[1] = b[1];
    a[2] = b[2];
}

static inline struct ethhdr *eth_hdr(const struct parse_buff *pab)
{
    return (struct ethhdr *)pab_mac_header(pab);
}

static inline struct tcphdr *tcp_hdr(const struct parse_buff *pab)
{
    return (struct tcphdr *)pab_transport_header(pab);
}

static inline struct udphdr *udp_hdr(const struct parse_buff *pab)
{
    return (struct udphdr *)pab_transport_header(pab);
}

static inline struct sctphdr *sctp_hdr(const struct parse_buff *pab)
{
    return (struct sctphdr *)pab_transport_header(pab);
}

static inline struct icmphdr *icmp_hdr(const struct parse_buff *pab)
{
    return (struct icmphdr *)pab_transport_header(pab);
}

static inline int ppab_may_pull(struct parse_buff *pab, unsigned int len)
{
    if (len <= pab_headlen(pab))
        return 1;
    else
        return 0;
}

static inline int check_header(struct parse_buff *pab, int len)
{
    if (pab->len < len)
        return -EINVAL;
    if (!ppab_may_pull(pab, len))
        return -ENOMEM;
    return 0;
}

static inline bool arphdr_ok(struct parse_buff *pab)
{
    return ppab_may_pull(pab, pab_network_offset(pab) +
            sizeof(struct arp_eth_header));
}

static inline int check_iphdr(struct parse_buff *pab)
{
    unsigned int nh_ofs = pab_network_offset(pab);
    unsigned int ip_len;
    int err;

    err = check_header(pab, nh_ofs + sizeof(struct iphdr));
    if (err)
        return err;

    ip_len = ip_hdrlen(pab);
    if (ip_len < sizeof(struct iphdr) ||
            pab->len < nh_ofs + ip_len)
        return -EINVAL;

    pab_set_transport_header(pab, nh_ofs + ip_len);
    return 0;
}

static inline bool tcphdr_ok(struct parse_buff *pab)
{
    int th_ofs = pab_transport_offset(pab);

    if (!ppab_may_pull(pab, th_ofs + sizeof(struct tcphdr)))
        return false;

    return true;
}

static inline bool udphdr_ok(struct parse_buff *pab)
{
    return ppab_may_pull(pab, pab_transport_offset(pab) +
            sizeof(struct udphdr));
}

static inline bool icmphdr_ok(struct parse_buff *pab)
{
    return ppab_may_pull(pab, pab_transport_offset(pab) +
            sizeof(struct icmphdr));
}

static inline uint8_t *pab_push(struct parse_buff *pab, unsigned int len)
{
    pab->data -= len;
    pab->len  += len;
    return pab->data;
}

static inline uint8_t *pab_pull(struct parse_buff *pab, unsigned int len)
{
    pab->len -= len;
    if (pab->len < pab->data_len)
    {
        VLOG_DBG("Trying to move pointer beyond the end of buffer");
        return pab->data += pab->data_len;
    }
    return pab->data += len;
}

static inline bool eth_p_mpls(uint16_t eth_type)
{
    return eth_type == htons(ETH_P_MPLS_UC) ||
        eth_type == htons(ETH_P_MPLS_MC);
}

#define VLAN_TAG_PRESENT        0x1000

static inline int parse_vlan(struct parse_buff *pab, struct pkt_info *key)
{
    struct qtag_prefix {
        uint16_t eth_type; /* ETH_P_8021Q */
        uint16_t tci;
    };
    struct qtag_prefix *qp;

    if (pab->len < sizeof(struct qtag_prefix) + sizeof(uint16_t))
        return 0;

    if (!ppab_may_pull(pab, sizeof(struct qtag_prefix) +
                sizeof(uint16_t)))
        return -ENOMEM;

    qp = (struct qtag_prefix *) pab->data;
    key->eth.tci = qp->tci | htons(VLAN_TAG_PRESENT);
    pab_pull(pab, sizeof(struct qtag_prefix));

    return 0;
}

static inline uint16_t pab_vlan_tag_present(struct parse_buff *pab)
{
    return ((pab)->vlan_tci & VLAN_TAG_PRESENT);
}

#define ETH_P_802_3_MIN 0x0600
static inline uint16_t parse_ethertype(struct parse_buff *pab)
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

    proto = *(uint16_t *) pab->data;
    pab_pull(pab, sizeof(uint16_t));

    proto &= htons(0xFF00);
    if (proto >= htons(ETH_P_802_3_MIN))
        return proto;

    if (pab->len < sizeof(struct llc_snap_hdr))
        return htons(ETH_P_802_2);

    if (!ppab_may_pull(pab, sizeof(struct llc_snap_hdr)))
        return htons(0);

    llc = (struct llc_snap_hdr *) pab->data;
    if (llc->dsap != LLC_SAP_SNAP ||
            llc->ssap != LLC_SAP_SNAP ||
            (llc->oui[0] | llc->oui[1] | llc->oui[2]) != 0)
        return htons(ETH_P_802_2);

    pab_pull(pab, sizeof(struct llc_snap_hdr));

    llc->ethertype &= htons(0xFF00);
    if (llc->ethertype >= htons(ETH_P_802_3_MIN))
        return llc->ethertype;

    return htons(ETH_P_802_2);
}

/* Extracts a key from an Ethernet frame.
 * pab: parse_buff that contains the frame, with pab->data pointing to the
 *      Ethernet header
 * key: output key
 *
 * The caller must ensure that pab->len >= ETH_HLEN.
 *
 * Returns 0 if successful, otherwise a negative errno value.
 *
 * Initializes pab header pointers as follows:
 *
 *    - pab->mac_header: the Ethernet header.
 *
 *    - pab->network_header: just past the Ethernet header, or just past the
 *      VLAN header, to the first byte of the Ethernet payload.
 *
 *    - pab->transport_header: If key->eth.type is ETH_P_IP or ETH_P_IPV6
 *      on output, then just past the IP header, if one is present and
 *      of a correct length, otherwise the same as pab->network_header.
 *      For other key->eth.type values it is left untouched.
 */
int key_extract(struct parse_buff *pab, struct pkt_info *key)
{
   int error;
   struct ethhdr *eth;

   /* Flags are always used as part of stats */
   key->tp.flags = 0;

   pab_reset_mac_header(pab);

   /* Link layer.  We are guaranteed to have at least the 14 byte Ethernet
    * header in the linear data area.
    */
   eth = eth_hdr(pab);
   ether_addr_copy(key->eth.src, eth->h_source);
   ether_addr_copy(key->eth.dst, eth->h_dest);

   pab_pull(pab, 2 * ETH_ALEN);
   /* We are going to push all headers that we pull, so no need to
    * update pab->csum here.
    */

   key->eth.tci = 0;
   if (pab_vlan_tag_present(pab))
      key->eth.tci = htons(vlan_get_tci(pab));
   else if (eth->h_proto == htons(ETH_P_8021Q))
      if (parse_vlan(pab, key))
         return -ENOMEM;

   key->eth.type = parse_ethertype(pab);
   if (key->eth.type == htons(0))
      return -ENOMEM;

   pab_reset_network_header(pab);
   pab_reset_mac_len(pab);
   pab_push(pab, pab->data - pab_mac_header(pab));

   /* Network layer. */
   if (key->eth.type == htons(ETH_P_IP)) {
      struct iphdr *nh;

      error = check_iphdr(pab);
      if (error) {
         memset(&key->ip, 0, sizeof(key->ip));
         memset(&key->ipv4, 0, sizeof(key->ipv4));
         if (error == -EINVAL) {
            pab->transport_header = pab->network_header;
            error = 0;
         }
         return error;
      }

      nh = ip_hdr(pab);
      key->ipv4.addr.src = htonl(nh->saddr);
      key->ipv4.addr.dst = htonl(nh->daddr);

      key->ip.proto = nh->protocol;
      key->ip.tos = nh->tos;
      key->ip.ttl = nh->ttl;

      /* Transport layer. */
      if (key->ip.proto == IPPROTO_TCP) {
         if (tcphdr_ok(pab)) {
            struct tcphdr *tcp = tcp_hdr(pab);
            key->tp.src = htons(tcp->source);
            key->tp.dst = htons(tcp->dest);
            key->tp.flags = TCP_FLAGS_BE16(*(uint16_t *)&(((union tcp_word_hdr *)(tcp))->words[3]));
         } else {
            memset(&key->tp, 0, sizeof(key->tp));
         }

      } else if (key->ip.proto == IPPROTO_UDP) {
         if (udphdr_ok(pab)) {
            struct udphdr *udp = udp_hdr(pab);
            key->tp.src = htons(udp->source);
            key->tp.dst = htons(udp->dest);
         } else {
            memset(&key->tp, 0, sizeof(key->tp));
         }
      } else if (key->ip.proto == IPPROTO_ICMP) {
         if (icmphdr_ok(pab)) {
            struct icmphdr *icmp = icmp_hdr(pab);
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
      bool arp_available = arphdr_ok(pab);

      arp = (struct arp_eth_header *)pab_network_header(pab);

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

         error = check_header(pab, pab->mac_len + stack_len);
         if (error)
            return 0;

         memcpy(&lse, pab_network_header(pab), MPLS_HLEN);

         if (stack_len == MPLS_HLEN)
            memcpy(&key->mpls.top_lse, &lse, MPLS_HLEN);

         pab_set_network_header(pab, pab->mac_len + stack_len);
         if (lse & htonl(MPLS_LS_S_MASK))
            break;

         stack_len += MPLS_HLEN;
      }
   } else if (key->eth.type == htons(ETH_P_IPV6)) {
      return -EPROTONOSUPPORT;
   }
   return 0;
}

void
acl_log_init()
{
      acllog_seqno = seq_read(acl_log_pktrx_seq_get());
      VLOG_DBG("ACL logging init");
}

void
acl_log_run(struct run_blk_params *blk_params)
{
    uint64_t seq;
    uint32_t timer_secs = atoi(ACL_LOG_TIMER_DEFAULT);
    long long int cur_time = time_msec();
    long long int timer_interval_ms;
    const char *timer_interval_str;
    const struct ovsrec_system *ovs;

    seq = seq_read(acl_log_pktrx_seq_get());

    /* Get the timer interval from the System table */
    ovs = ovsrec_system_first(blk_params->idl);
    if (ovs) {
        timer_interval_str = smap_get(&ovs->other_config, ACL_LOG_TIMER_STR);
        if (timer_interval_str) {
            timer_secs = atoi(timer_interval_str);
        }
        /* if it is not found, use the default value */
    } else {
        VLOG_WARN("Unable to read from database");
    }
    timer_interval_ms = timer_secs * 1000;

    if ((start_time == LLONG_MAX) || (start_time == LLONG_MIN)) {
        /* check to see if a packet was received for logging */
        struct pkt_info key;
        struct parse_buff pkt_buff;
        int ace_seq_no;
        struct ds msg;

        /* We are in the state where we are waiting for packets, but we have
         * not received any packets, so return. */
        if (seq == acllog_seqno) {
            return;
        }

        ds_init(&msg);
        memset(&key, 0, sizeof(key));
        memset(&pkt_buff, 0, sizeof(pkt_buff));

        VLOG_DBG("ACL log packet received");
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
        if (!(ACL_LOG_LIST_NAME & pkt_buff.pkt_info.valid_fields)) {
            /* TODO: get ACL name from port number */
            snprintf(pkt_buff.pkt_info.list_name,
                    sizeof(pkt_buff.pkt_info.list_name),
                    "Unavailable"); /* change me later */
            pkt_buff.pkt_info.valid_fields |= ACL_LOG_LIST_NAME;
        }
        if (ACL_LOG_LIST_NAME & pkt_buff.pkt_info.valid_fields) {
            ds_put_format(&msg, "List %s, ", pkt_buff.pkt_info.list_name);
        }

        if (!(ACL_LOG_ENTRY_NUM & pkt_buff.pkt_info.valid_fields)) {
            /* dummy for now */
            pkt_buff.pkt_info.entry_num = 0; /* change me later */
            pkt_buff.pkt_info.valid_fields |= ACL_LOG_ENTRY_NUM;
        }
        if (ACL_LOG_ENTRY_NUM & pkt_buff.pkt_info.valid_fields) {
            /* needs to be properly converted */
            ace_seq_no = pkt_buff.pkt_info.entry_num;
            ds_put_format(&msg, "seq#%d ", ace_seq_no);
        }

        /* only deny logging is currently supported */
        ds_put_format(&msg, "%s ", "denied");
        ds_put_format(&msg, "%s ",
                        acl_parse_protocol_get_name_from_number(key.ip.proto));

        ds_put_format(&msg, "%d.%d.%d.%d",
                    (key.ipv4.addr.src >> 24) & 0xff,
                    (key.ipv4.addr.src >> 16) & 0xff,
                    (key.ipv4.addr.src >> 8) & 0xff,
                    key.ipv4.addr.src & 0xff);
        if ((key.ip.proto == IPPROTO_UDP) || (key.ip.proto == IPPROTO_TCP)) {
            ds_put_format(&msg, "(%d)", key.tp.src);
        }
        ds_put_format(&msg, "%d.%d.%d.%d",
                    (key.ipv4.addr.dst >> 24) & 0xff,
                    (key.ipv4.addr.dst >> 16) & 0xff,
                    (key.ipv4.addr.dst >> 8) & 0xff,
                    key.ipv4.addr.dst & 0xff);
        if ((key.ip.proto == IPPROTO_UDP) || (key.ip.proto == IPPROTO_TCP)) {
            ds_put_format(&msg, "(%d) ", key.tp.dst);
        } else if (key.ip.proto == IPPROTO_ICMP) {
            ds_put_format(&msg, " type %d code %d, ", key.tp.src, key.tp.dst);
        }
        ds_put_format(&msg, "on vlan %d, port %d",
                    pkt_buff.pkt_info.ingress_vlan,
                    pkt_buff.pkt_info.ingress_port);
        VLOG_INFO("%s", ds_cstr_ro(&msg));
        ds_destroy(&msg);

        if (start_time == LLONG_MIN)
        {
            /* this is the first time receiving a packet, so the ACEs may have
             * non-zero counts that we have not previously stored */
            /* TODO: record statistics */
        }
        /* start the timer */
        start_time = cur_time;
        prev_timer_interval_ms = timer_interval_ms;
        poll_timer_wait_until(start_time + timer_interval_ms);
    } else if ((start_time + timer_interval_ms) <= cur_time) {
        /* the timer has expired */
        VLOG_DBG("ACL log timer expired");

        /* TODO */
        /* 1. get the statistics for ACEs with the log action */
        /* 2. print diffs */
        /* 3. update previous counts */

        /* start receiving packets again */
        start_time = LLONG_MAX;
    } else if (!(start_time == LLONG_MAX) &&
            (prev_timer_interval_ms != timer_interval_ms)) {

        VLOG_DBG("ACL log timer changed from %d to %lld - updating timeout",
                 prev_timer_interval_ms, timer_interval_ms);

        prev_timer_interval_ms = timer_interval_ms;
        poll_timer_wait_until(start_time + timer_interval_ms);
    }

    acllog_seqno = seq;
}

void
acl_log_wait(struct run_blk_params *blk_params)
{
    seq_wait(acl_log_pktrx_seq_get(), acllog_seqno);
}
