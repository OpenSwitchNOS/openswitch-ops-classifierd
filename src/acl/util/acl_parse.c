/*
 * Copyright (C) 2016 Hewlett Packard Enterprise Development LP
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

#include "acl_parse.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(acl_parse);

/** Static map of protocols whose string names are supported */
static const char * const protocol_names[] = {
       "0", "icmp", "igmp",    "3",    "4",    "5",  "tcp",    "7",
       "8",    "9",   "10",   "11",   "12",   "13",   "14",   "15",
      "16",  "udp",   "18",   "19",   "20",   "21",   "22",   "23",
      "24",   "25",   "26",   "27",   "28",   "29",   "30",   "31",
      "32",   "33",   "34",   "35",   "36",   "37",   "38",   "39",
      "40",   "41",   "42",   "43",   "44",   "45",   "46",  "gre",
      "48",   "49",  "esp",   "ah",   "52",   "53",   "54",   "55",
      "56",   "57",   "58",   "59",   "60",   "61",   "62",   "63",
      "64",   "65",   "66",   "67",   "68",   "69",   "70",   "71",
      "72",   "73",   "74",   "75",   "76",   "77",   "78",   "79",
      "80",   "81",   "82",   "83",   "84",   "85",   "86",   "87",
      "88",   "89",   "90",   "91",   "92",   "93",   "94",   "95",
      "96",   "97",   "98",   "99",  "100",  "101",  "102",  "pim",
     "104",  "105",  "106",  "107",  "108",  "109",  "110",  "111",
     "112",  "113",  "114",  "115",  "116",  "117",  "118",  "119",
     "120",  "121",  "122",  "123",  "124",  "125",  "126",  "127",
     "128",  "129",  "130",  "131", "sctp",  "133",  "134",  "135",
     "136",  "137",  "138",  "139",  "140",  "141",  "142",  "143",
     "144",  "145",  "146",  "147",  "148",  "149",  "150",  "151",
     "152",  "153",  "154",  "155",  "156",  "157",  "158",  "159",
     "160",  "161",  "162",  "163",  "164",  "165",  "166",  "167",
     "168",  "169",  "170",  "171",  "172",  "173",  "174",  "175",
     "176",  "177",  "178",  "179",  "180",  "181",  "182",  "183",
     "184",  "185",  "186",  "187",  "188",  "189",  "190",  "191",
     "192",  "193",  "194",  "195",  "196",  "197",  "198",  "199",
     "200",  "201",  "202",  "203",  "204",  "205",  "206",  "207",
     "208",  "209",  "210",  "211",  "212",  "213",  "214",  "215",
     "216",  "217",  "218",  "219",  "220",  "221",  "222",  "223",
     "224",  "225",  "226",  "227",  "228",  "229",  "230",  "231",
     "232",  "233",  "234",  "235",  "236",  "237",  "238",  "239",
     "240",  "241",  "242",  "243",  "244",  "245",  "246",  "247",
     "248",  "249",  "250",  "251",  "252",  "253",  "254",  "255"
};

const char *
protocol_get_name_from_number(uint8_t proto_number)
{
    return protocol_names[proto_number];
}

bool
str_is_numeric(const char *in_str)
{
    /* Null check. May not be necessary here */
    if (!*in_str) {
        return false;
    }

    /* Check if every character in the string is a digit */
    while (*in_str) {
        if (!isdigit(*in_str)) {
            return false;
        }
        ++in_str;
    }

    return true;
}

uint8_t
protocol_get_number_from_name(const char *in_proto)
{
    uint8_t protocol = ACL_PROTOCOL_INVALID;

    if (!in_proto) {
        VLOG_DBG("Null protocol string specified");
        return protocol;
    }

    if (!strcmp(in_proto, "ah")) {
        protocol = ACL_PROTOCOL_AH;
    } else if (!strcmp(in_proto, "esp")) {
        protocol = ACL_PROTOCOL_ESP;
    } else if (!strcmp(in_proto, "icmp")) {
        protocol = ACL_PROTOCOL_ICMP;
    } else if (!strcmp (in_proto, "icmpv6")) {
        protocol = ACL_PROTOCOL_ICMPV6;
    } else if (!strcmp (in_proto, "igmp")) {
        protocol = ACL_PROTOCOL_IGMP;
    } else if (!strcmp (in_proto, "pim")) {
        protocol = ACL_PROTOCOL_PIM;
    } else  if (!strcmp (in_proto, "sctp")) {
        protocol = ACL_PROTOCOL_SCTP;
    } else if (!strcmp (in_proto, "tcp")) {
        protocol = ACL_PROTOCOL_TCP;
    } else if (!strcmp (in_proto, "udp")) {
        protocol = ACL_PROTOCOL_UDP;
    } else {
        VLOG_DBG("Invalid protocol specified %s", in_proto);
        protocol = ACL_PROTOCOL_INVALID;
    }

    return protocol;
}

in_addr_t
ipv4_mask_create(uint8_t prefix_len)
{
    /* bit twiddling ideas from:
     * http://stackoverflow.com/questions/20263860/ipv4-prefix-length-to-netmask
     *
     *          1 << (32 - prefix_len)
     * 32 -> 0b00000000 00000000 00000000 00000001
     * 24 -> 0b00000000 00000000 00000001 00000000
     *  1 -> 0b10000000 00000000 00000000 00000000
     *
     *          (1 << (32 - prefix_len)) - 1
     * 32 -> 0b00000000 00000000 00000000 00000000
     * 24 -> 0b00000000 00000000 00000000 11111111
     *  1 -> 0b01111111 11111111 11111111 11111111
     *
     *        ~((1 << (32 - prefix_len)) - 1)
     * 32 -> 0b11111111 11111111 11111111 11111111
     * 24 -> 0b11111111 11111111 11111111 00000000
     *  1 -> 0b10000000 00000000 00000000 00000000
     */
    return prefix_len ? htonl(~((0x1u << (32 - prefix_len)) - 1)) : 0;
}

bool
acl_ipv4_address_user_to_normalized(const char *user_str, char *normalized_str)
{
    char addr_str[INET_ADDRSTRLEN*2];
    char *slash_ptr;
    char *mask_substr = NULL;
    struct in_addr v4_addr;
    struct in_addr v4_mask;
    int addr_str_len;
    uint8_t prefix_len;

    if (!strcmp(user_str, "any")) {
        return NULL;
    }

    /* Get a copy of the string we can do destructive things to */
    memcpy(addr_str, user_str, sizeof(INET_ADDRSTRLEN*2));

    /* Find the slash character (if any) */
    slash_ptr = strchr(addr_str, '/');
    if (slash_ptr) {
        slash_ptr[0] = '\0';
        mask_substr = &slash_ptr[1];
    }
    /* Normalize via standard library calls */
    if (!inet_pton(AF_INET, addr_str, &v4_addr)) {
        VLOG_ERR("Invalid IPv4 address string %s", addr_str);
        return false;
    }
    if (!inet_ntop(AF_INET, &v4_addr, normalized_str, INET_ADDRSTRLEN)) {
        VLOG_ERR("Invalid IPv4 address value %s", addr_str);
        return false;
    }
    /* Process subnet mask (either prefix length or dotted-decimal notation) */
    if (mask_substr) {
        /* Prefix length */
        if (str_is_numeric(mask_substr)) {
            prefix_len = strtoul(mask_substr, NULL, 0);
            if (prefix_len > 32) {
                VLOG_ERR("Invalid IPv4 prefix length %d", prefix_len);
                return false;
            }
            /* Set the mask based on the prefix_len */
            v4_mask.s_addr = ipv4_mask_create(prefix_len);
        /* Dotted-decimal */
        } else {
            /* Normalize via standard library call */
            if (!inet_pton(AF_INET, mask_substr, &v4_mask)) {
                VLOG_ERR("Invalid IPv4 dotted-decimal mask %s", mask_substr);
                return false;
            }
        }
        /* Add '/' after address and append dotted-decimal netmask */
        addr_str_len = strlen(normalized_str);
        normalized_str[addr_str_len] = '/';
        /* Normalize via standard library call */
        if (!inet_ntop(AF_INET, &v4_mask, &normalized_str[addr_str_len+1], INET_ADDRSTRLEN)) {
            VLOG_ERR("Invalid IPv4 mask %s", mask_substr);
            return false;
        }
    }
    return true;
}

bool
acl_parse_ipv4_address(const char *in_address,
                   enum ops_cls_list_entry_flags flag,
                   uint32_t *flags,
                   struct in_addr *v4_addr,
                   struct in_addr *v4_mask,
                   enum ops_cls_addr_family *family)
{
    /* TODO: support more formats
     *   - For now only support x.x.x.x and x.x.x.x/d
     */
    if (!strcmp(in_address, "any")) {
        /* we leave zero'd fields alone for "any" */
    } else {
        *flags |= flag;
        *family = OPS_CLS_AF_INET;

        /* see if we have the 10.0.0.1/24 format */
        char *copy_address = NULL;
        const char *hstr;
        char *pstr = strchr(in_address, '/');
        const uint8_t max_prefix_len = 32;
        int prefix_len;
        if (pstr) {
            /* make a copy we can munge */
            copy_address = xstrdup(in_address);
            pstr = copy_address + (pstr - in_address);
            hstr = copy_address;

            *pstr++ = '\0'; /* overwrite '/' to terminate hstr */
            prefix_len = atoi(pstr);
            if (prefix_len > max_prefix_len) {
                VLOG_ERR("Bad prefixlen %d > %d", prefix_len, max_prefix_len);
                free(copy_address);
                return false;
            }
        } else {
            /* plain hostname, just work off original in_address */
            hstr = in_address;

            prefix_len = max_prefix_len;
        }

        /* Set the mask based on the prefix_len */
        v4_mask->s_addr = ipv4_mask_create(prefix_len);

        /* parse the actual address part */
        if (inet_pton(AF_INET, hstr, v4_addr) == 0) {
            VLOG_ERR("Invalid ip address %s", in_address);
            free(copy_address);
            return false;
        }

        free(copy_address);

    }

    return true;
}

bool
acl_parse_protocol(const char *in_proto,
                   enum ops_cls_list_entry_flags flag,
                   uint32_t *flags,
                   uint8_t *proto)
{
    if (!strcmp(in_proto, "any")) {
        /* we leave zero'd fields alone for "any" */
    } else {
        *flags |= flag;

        /* Check if the protocol is a number */
        if (str_is_numeric(in_proto)) {
            *proto = strtoul(in_proto, NULL, 10);
        } else {
            /* Protocol is a name. Map it to the correct protocol number */
            *proto = protocol_get_number_from_name(in_proto);
            if (*proto == ACL_PROTOCOL_INVALID)
            {
                VLOG_ERR("Invalid protocol %s", in_proto);
                return false;
            }
        }
    }
    VLOG_DBG("classifier: protocol = %d", *proto);
    return true;
}

bool
acl_parse_actions(const char *in_action,
                  struct ops_cls_list_entry_actions *actions)
{
    /* TODO: handle empty action */
    /* TODO: handle conflicting actions (e.g. permit and deny) */

    if (strstr(in_action, "permit")) {
        actions->action_flags |= OPS_CLS_ACTION_PERMIT;
    }

    if (strstr(in_action, "deny")) {
        actions->action_flags |= OPS_CLS_ACTION_DENY;
    }

    if (strstr(in_action, "log")) {
        actions->action_flags |= OPS_CLS_ACTION_LOG;
    }

    if (strstr(in_action, "count")) {
        actions->action_flags |= OPS_CLS_ACTION_COUNT;
    }

    return true;
}

bool
acl_parse_l4_port(const char *in_port, uint16_t *port)
{
    /* TODO: check return codes to detect if not even in integer format */
    uint64_t tmp = strtoul(in_port, NULL, 10);
    if (tmp > UINT16_MAX) {
        VLOG_ERR("Invalid L4 port %s", in_port);
        return false;
    }
    *port = tmp;

    VLOG_DBG("classifier: L4 port = %u", *port);
    return true;
}

/* TODO: Remove these once the schema parser can generate them for us */
#ifndef OPS_CLS_L4_PORT_OP_EQ_STR
#define OPS_CLS_L4_PORT_OP_EQ_STR "eq"
#define OPS_CLS_L4_PORT_OP_NEQ_STR "neq"
#define OPS_CLS_L4_PORT_OP_LT_STR "lt"
#define OPS_CLS_L4_PORT_OP_GT_STR "gt"
#define OPS_CLS_L4_PORT_OP_RANGE_STR "range"
#endif

bool
acl_parse_l4_operator(const char *in_op, enum ops_cls_list_entry_flags flag,
                      uint32_t *flags, enum ops_cls_L4_operator *op)
{
    *flags |= flag;

    if (strcmp(OPS_CLS_L4_PORT_OP_EQ_STR, in_op)==0) {
        *op = OPS_CLS_L4_PORT_OP_EQ;
    } else if (strcmp(OPS_CLS_L4_PORT_OP_NEQ_STR, in_op)==0) {
        *op = OPS_CLS_L4_PORT_OP_NEQ;
    } else if (strcmp(OPS_CLS_L4_PORT_OP_LT_STR, in_op)==0) {
        *op = OPS_CLS_L4_PORT_OP_LT;
    } else if (strcmp(OPS_CLS_L4_PORT_OP_GT_STR, in_op)==0) {
        *op = OPS_CLS_L4_PORT_OP_GT;
    } else if (strcmp(OPS_CLS_L4_PORT_OP_RANGE_STR, in_op)==0) {
        *op = OPS_CLS_L4_PORT_OP_RANGE;
    } else {
        VLOG_ERR("Invalid L4 operator %s", in_op);
        return false;
    }
    VLOG_DBG("classifier: L4 operator = %d", *op);
    return true;
}
