/*
 * Copyright (C) 1997, 98 Kunihiro Ishiguro
 * Copyright (C) 2015, 2016 Hewlett Packard Enterprise Development LP
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/************************************************************************//**
 * @ingroup ops-access-list
 *
 * @file
 * Implementation of Access Control List (ACL) CLI functions
 ***************************************************************************/

#include <vtysh/command.h>
#include <vtysh/memory.h>
#include <vtysh/vtysh.h>
#include <vtysh/vtysh_user.h>
#include <vtysh/vtysh_ovsdb_if.h>
#include <vtysh/vtysh_ovsdb_config.h>
#include <vtysh/vty_utils.h>

#include <openvswitch/vlog.h>
#include <smap.h>
#include <hmap.h>
#include <json.h>
#include <dynamic-string.h>
#include <latch.h>
#include <timer.h>

#include <vswitch-idl.h>
#include <ovsdb-idl.h>
#include <openswitch-idl.h>

#include "ops-cls-asic-plugin.h"
#include "ops_cls_status_msgs.h"
#include "acl_parse.h"
#include "access_list_vty.h"

/** Create logging module */
VLOG_DEFINE_THIS_MODULE(vtysh_access_list_cli);

/** Utilize OVSDB interface code generated from schema */
extern struct ovsdb_idl *idl;

/* = Private Constants = */

/* Misc constants */
#define MAX_ACL_NAME_LENGTH 65 /**< 64 character name + NULL-terminator */
#define IP_VER_STR_LEN 5       /**< "ipv{4|6}" + NULL-terminator */
#define ACL_TRUE_STR "true"

/* Log timer constants */
#define ACL_LOG_TIMER_DEFAULT_STR "default"

/* Constants related to ACE sequence numbers */
#define ACE_SEQ_MAX 4294967295 /**< Maximum sequence number allowed for an ACE */
#define ACE_SEQ_MAX_STR_LEN 11 /**< ACE_SEQ_MAX in a string + NULL-terminator */
#define ACE_SEQ_AUTO_INCR   10 /**< Amount to increment new ACEs automatically by */

/* https://gcc.gnu.org/onlinedocs/cpp/Stringification.html#Stringification */
#define ACL_NUM_TO_STR_HELPER(x) #x                /**< Preprocessor helper macro */
#define ACL_NUM_TO_STR(x) ACL_NUM_TO_STR_HELPER(x) /**< Preprocessor stringify macro */

/* Common help strings */
#define ACL_STR "Access control list (ACL)\n"
#define ACL_NAME_STR "ACL name\n"
#define ACL_CFG_STR "Display ACL configuration as CLI commands\n"
#define ACL_HITCOUNTS_STR "Hit counts (statistics)\n"
#define ACL_IN_STR "Inbound (ingress) traffic\n"
#define ACL_APPLY_STR "Apply a configuration record\n"
#define ACL_IP_STR "Internet Protocol v4 (IPv4)\n"
#define ACL_INTERFACE_STR "Specify interface\n"
#define ACL_INTERFACE_NAME_STR "Interface Name\n"
#define ACL_INTERFACE_ID_STR "Identifier (Interface Name or VLAN ID)\n"
#define ACL_VLAN_STR "Specify VLAN\n"
#define ACL_VLAN_ID_STR "VLAN ID\n"
#define ACL_ALL_STR "All access-lists\n"

/* Command strings (cmdstr) and Help strings (helpstr) used in vtysh DEFUNs */
#define ACE_SEQ_CMDSTR "<1-" ACL_NUM_TO_STR(ACE_SEQ_MAX) "> "
#define ACE_SEQ_HELPSTR "Access control entry (ACE) sequence number\n"
#define ACE_ACTION_CMDSTR "(deny | permit) "
#define ACE_ACTION_HELPSTR "Deny packets matching this ACE\n" \
                           "Permit packets matching this ACE\n"
#define ACE_ALL_PROTOCOLS_CMDSTR "(any | ah | gre | esp | icmp | igmp |  pim | sctp | tcp | udp | <0-255>) "
#define ACE_ALL_PROTOCOLS_HELPSTR "Any internet protocol number\n" \
                                  "Authenticated header\n" \
                                  "Generic routing encapsulation\n" \
                                  "Encapsulation security payload\n" \
                                  "Internet control message protocol\n" \
                                  "Internet group management protocol\n" \
                                  "Protocol independent multicast\n" \
                                  "Stream control transport protocol\n" \
                                  "Transport control protocol\n" \
                                  "User datagram protocol\n" \
                                  "Specify numeric protocol value\n"
#define ACE_PORT_PROTOCOLS_CMDSTR  "(sctp | tcp | udp) "
#define ACE_PORT_PROTOCOLS_HELPSTR "Stream control transport protocol\n" \
                                   "Transport control protocol\n" \
                                   "User datagram protocol\n"
#define ACE_IP_ADDRESS_CMDSTR "(any | A.B.C.D | A.B.C.D/M | A.B.C.D/W.X.Y.Z) "
#define ACE_SRC_IP_ADDRESS_HELPSTR "Any source IP address\n" \
                                   "Specify source IP host address\n" \
                                   "Specify source IP network address with prefix length\n" \
                                   "Specify source IP network address with network mask\n"
#define ACE_DST_IP_ADDRESS_HELPSTR "Any destination IP address\n" \
                                   "Specify destination IP host address\n" \
                                   "Specify destination IP network address with prefix length\n" \
                                   "Specify destination IP network address with network mask\n"
#define ACE_PORT_OPER_CMDSTR "(eq | gt | lt | neq) <0-65535> "
#define ACE_SRC_PORT_OPER_HELPSTR "Layer 4 source port equal to\n" \
                                  "Layer 4 source port greater than\n" \
                                  "Layer 4 source port less than\n" \
                                  "Layer 4 source port not equal to\n" \
                                  "Layer 4 source port\n"
#define ACE_DST_PORT_OPER_HELPSTR "Layer 4 destination port equal to\n" \
                                  "Layer 4 destination port greater than\n" \
                                  "Layer 4 destination port less than\n" \
                                  "Layer 4 destination port not equal to\n" \
                                  "Layer 4 destination port\n"
#define ACE_PORT_RANGE_CMDSTR "(range) <0-65535> <0-65535> "
#define ACE_SRC_PORT_RANGE_HELPSTR "Layer 4 source port range\n" \
                                   "Layer 4 source minimum port\n" \
                                   "Layer 4 source maximum port\n"
#define ACE_DST_PORT_RANGE_HELPSTR "Layer 4 destination port range\n" \
                                   "Layer 4 destination minimum port\n" \
                                   "Layer 4 destination maximum port\n"
#define ACE_ADDITIONAL_OPTIONS_CMDSTR "{ log | count }"
#define ACE_ADDITIONAL_OPTIONS_HELPSTR "Log packets matching this entry (will also enable 'count')\n" \
                                       "Count packets matching this entry\n"
#define ACE_COMMENT_CMDSTR "(comment) "
#define ACE_COMMENT_HELPSTR "Set a text comment for a new or existing ACE\n"
#define ACE_COMMENT_TEXT_CMDSTR ".TEXT"
#define ACE_COMMENT_TEXT_HELPSTR "Comment text\n"
#define ACE_ETC_CMDSTR "...."
#define ACE_ETC_HELPSTR "(ignored)\n"

/* = Static/Helper functions = */

/**
 * Look up an ACL by type + name
 *
 * @param  acl_type ACL type string
 * @param  acl_name ACL name string
 *
 * @return          Pointer to ovsrec_acl structure object
 *
 * @todo This is not a very performant way to get a row by index columns.
 *       Initially it was the only way to do so; replace with something
 *       more efficient.
 */
static inline const struct ovsrec_acl *
get_acl_by_type_name(const char *acl_type, const char *acl_name)
{
    const static struct ovsrec_acl *acl;

    OVSREC_ACL_FOR_EACH(acl, idl) {
        if ((!strcmp(acl->list_type, acl_type)) &&
            (!strcmp(acl->name, acl_name))) {
            return (struct ovsrec_acl *) acl;
        }
    }

    return NULL;
}

/**
 * Look up an ACE by key (sequence number) in current ACEs
 *
 * @param  acl_row         ACL row pointer
 * @param  sequence_number ACE sequence number
 *
 * @return                 Pointer to ovsrec_acl_entry structure object
 *
 * @todo This could/should be generated as part of IDL.
 */
static inline const struct ovsrec_acl_entry*
ovsrec_acl_cur_aces_getvalue(const struct ovsrec_acl *acl_row,
                             const int64_t key)
{
    int i;
    for (i = 0; i < acl_row->n_cur_aces; i ++) {
        if (acl_row->key_cur_aces[i] == key) {
            return acl_row->value_cur_aces[i];
        }
    }
    return NULL;
}

/**
 * Look up an ACE by key (sequence number) in ACE statistics
 *
 * @param  port_row        Port row pointer
 * @param  sequence_number ACE sequence number
 *
 * @return                 Hit count for ACE, 0 on failure
 *
 * @todo This could/should be generated as part of IDL.
 */
static inline const int64_t
ovsrec_port_aclv4_in_statistics_getvalue(const struct ovsrec_port *port_row,
                                         const int64_t key)
{
    int i;
    for (i = 0; i < port_row->n_aclv4_in_statistics; i ++) {
        if (port_row->key_aclv4_in_statistics[i] == key) {
            return port_row->value_aclv4_in_statistics[i];
        }
    }
    return 0;
}

/**
 * Look up an ACE by key (sequence number) in ACE statistics
 *
 * @param  vlan_row        VLAN row pointer
 * @param  sequence_number ACE sequence number
 *
 * @return                 Hit count for ACE, 0 on failure
 *
 * @todo This could/should be generated as part of IDL.
 */
static inline const int64_t
ovsrec_vlan_aclv4_in_statistics_getvalue(const struct ovsrec_vlan *vlan_row,
                                         const int64_t key)
{
    int i;
    for (i = 0; i < vlan_row->n_aclv4_in_statistics; i ++) {
        if (vlan_row->key_aclv4_in_statistics[i] == key) {
            return vlan_row->value_aclv4_in_statistics[i];
        }
    }
    return 0;
}

/**
 * Take ACL Entries from an ACL's cur_aces, copy them into cfg_aces, and update
 * the provided entry with a new value.
 *
 * @param acl_row ACL row pointer
 * @param key     numeric key (entry sequence number)
 * @param value   ACL Entry row pointer (NULL indicates delete)
 *
 * @return        false if attempting to delete a non-existent entry,
 *                true otherwise
 */
static inline bool
ovsrec_acl_set_cfg_aces_from_cur_aces(const struct ovsrec_acl *acl_row,
                                      const int64_t key,
                                      struct ovsrec_acl_entry *value)
{
    /* Assume we may add an entry until we find out this is an update or delete */
    int entries_changed = 1;
    /* malloc one extra entry key-value pair in case we insert */
    int64_t *key_list = xmalloc(sizeof(int64_t) * (acl_row->n_cur_aces + entries_changed));
    struct ovsrec_acl_entry **value_list = xmalloc(sizeof *acl_row->value_cur_aces * (acl_row->n_cur_aces + entries_changed));
    int cur_idx, cfg_idx;

    for (cur_idx = 0, cfg_idx = 0; cur_idx < acl_row->n_cur_aces; cur_idx++) {
        if (key == acl_row->key_cur_aces[cur_idx]) {
            /* For update, use provided value instead of cur_aces value */
            if (value != NULL) {
                key_list[cfg_idx] = key;
                value_list[cfg_idx] = value;
                entries_changed = 0;
                cfg_idx++;
            /* For delete operation, don't copy into cfg_aces or bump cfg_idx*/
            } else {
                entries_changed = -1;
            }
        } else {
            /* For all other entries, copy cur_aces to cfg_aces */
            key_list[cfg_idx] = acl_row->key_cur_aces[cur_idx];
            value_list[cfg_idx] = acl_row->value_cur_aces[cur_idx];
            cfg_idx++;
        }
    }
    /* If matching entry key was not found */
    if (entries_changed > 0) {
        /* Check if it was a delete where the value wasn't found */
        if (!value) {
            free(key_list);
            free(value_list);
            return false;
        }
        /* Not an update or delete, so it's an insert. Append entry to list
           (will be sorted by key automatically). */
        key_list[acl_row->n_cur_aces] = key;
        value_list[acl_row->n_cur_aces] = value;
    }
    ovsrec_acl_set_cfg_aces(acl_row, key_list, value_list, acl_row->n_cur_aces + entries_changed);
    free(key_list);
    free(value_list);
    return true;
}

/**
 * Look up a Port by name
 *
 * @param  name     Port name string
 *
 * @return          Pointer to ovsrec_port structure object
 *
 * @todo This is not a very performant way to get a row by indexed columns.
 *       Initially it was the only way to do so; replace with something
 *       more efficient.
 */
static inline const struct ovsrec_port *
get_port_by_name(const char *name)
{
    const static struct ovsrec_port *port;

    OVSREC_PORT_FOR_EACH(port, idl) {
        if (!strcmp(port->name, name)) {
            return (struct ovsrec_port *) port;
        }
    }

    return NULL;
}

/**
 * Look up a VLAN by ID (in string form)
 *
 * @param  id_str   VLAN ID string
 *
 * @return          Pointer to ovsrec_vlan structure object
 *
 * @todo This is not a very performant way to get a row by indexed columns.
 *       Initially it was the only way to do so; replace with something
 *       more efficient.
 */
static inline const struct ovsrec_vlan *
get_vlan_by_id_str(const char *id_str)
{
    const static struct ovsrec_vlan *vlan;

    OVSREC_VLAN_FOR_EACH(vlan, idl) {
        if (vlan->id == strtoul(id_str, NULL, 0)) {
            return (struct ovsrec_vlan *) vlan;
        }
    }

    return NULL;
}

/* = OVSDB Manipulation Functions = */

/**
 * Add IP address config information to an ACE dynamic string
 *
 * @param dstring      Pointer to initialized dynamic string
 * @param address_str  Pointer to IP address string
 */
static void
acl_entry_ip_address_config_to_ds(struct ds *dstring, char *address_str)
{
    char user_str[INET_ADDRSTRLEN*2];
    if(acl_ipv4_address_normalized_to_user(address_str, user_str))
    {
        ds_put_format(dstring, "%s ", user_str);
    }
}

/**
 * Add L4 port config information to an ACE dynamic string
 *
 * @param dstring  Pointer to initialized dynamic string
 * @param min      First port number
 * @param max      Last port number
 * @param reverse  Whether range is reversed
 */
static void
acl_entry_l4_port_config_to_ds(struct ds *dstring,
                               int64_t min, int64_t max, bool reverse)
{
    if (min == max) {
        if (reverse) {
            ds_put_format(dstring, "%s %" PRId64 " ", "neq", min);
        } else {
            ds_put_format(dstring, "%s %" PRId64 " ", "eq", min);
        }
    } else if (min == 0 && max < 65535) {
        ds_put_format(dstring, "%s %" PRId64 " ", "lt", max + 1);
    } else if (min > 0 && max == 65535) {
        ds_put_format(dstring, "%s %" PRId64 " ", "gt", min - 1);
    } else {
        ds_put_format(dstring, "%s %" PRId64 " %" PRId64 " ", "range", min, max);
    }
}

/**
 * Creates a string with an ACL Entry config as if it were entered into the CLI
 *
 * @param sequence_num  ACL Entry Sequence number
 * @param ace_row       Pointer to ACL_Entry row
 *
 * @return              ACL Entry string, caller-freed, not newline-terminated
 */
static char *
acl_entry_config_to_string(const int64_t sequence_num,
                           const struct ovsrec_acl_entry *ace_row)
{
    struct ds dstring;
    ds_init(&dstring);

    ds_put_format(&dstring, "%" PRId64 " ", sequence_num);
    ds_put_format(&dstring, "%s ", ace_row->action);
    if (ace_row->n_protocol != 0) {
        ds_put_format(&dstring, "%s ", acl_parse_protocol_get_name_from_number(ace_row->protocol[0]));
    }
    if (ace_row->src_ip) {
        acl_entry_ip_address_config_to_ds(&dstring, ace_row->src_ip);
    }
    if (ace_row->n_src_l4_port_min && ace_row->n_src_l4_port_max) {
        acl_entry_l4_port_config_to_ds(&dstring,
                                       ace_row->src_l4_port_min[0],
                                       ace_row->src_l4_port_max[0],
                                       ace_row->n_src_l4_port_range_reverse);
    }
    if (ace_row->dst_ip) {
        acl_entry_ip_address_config_to_ds(&dstring, ace_row->dst_ip);
    }
    if (ace_row->n_dst_l4_port_min && ace_row->n_dst_l4_port_max) {
        acl_entry_l4_port_config_to_ds(&dstring,
                                       ace_row->dst_l4_port_min[0],
                                       ace_row->dst_l4_port_max[0],
                                       ace_row->n_dst_l4_port_range_reverse);
    }
    if (ace_row->log) {
        ds_put_format(&dstring, "log ");
    /* Log implies count, only print count if not logging */
    } else if (ace_row->count) {
        ds_put_format(&dstring, "count ");
    }
    return ds_steal_cstr(&dstring);
}

/**
 * Check ACL entry capacity for any given ACL and in database table
 *
 * @param acl_row Pointer to ACL row
 * @param ace_row Pointer to ACE row
 *
 * @retval CMD_SUCCESS           on success
 * @retval CMD_OVSDB_FAILURE     on database/transaction failure
 * @retval CMD_ERR_NOTHING_TODO  on ACE capacity failure
 */
static int
check_ace_capacity (const struct ovsrec_acl *acl_row,
                    const struct ovsrec_acl_entry *ace_row)
{
    const struct ovsrec_system *ovs;
    const char* max_aces_str;
    const char* max_aces_per_acl_str;
    int64_t max_aces, max_aces_per_acl;
    const struct ovsdb_idl_row *ace_header;
    size_t ace_entries;

    /* Get System table */
    ovs = ovsrec_system_first(idl);

    if (!ovs) {
        VLOG_ERR("Unable to acquire system table.");
        assert(0);
        return CMD_OVSDB_FAILURE;
    }

    /* Get max ACEs and max ACEs per acl from system table, other config */
    max_aces_str = smap_get(&ovs->other_config, "max_aces");
    max_aces_per_acl_str = smap_get(&ovs->other_config, "max_aces_per_acl");

    if (max_aces_str && max_aces_per_acl_str) {
        max_aces = strtol(max_aces_str, NULL, 0);
        max_aces_per_acl = strtol(max_aces_per_acl_str, NULL, 0);
    } else {
        VLOG_ERR("Unable to acquire ACE hardware limits.");
        return CMD_OVSDB_FAILURE;
    }

    /* Get number of ACEs in database from table header */
    ace_header = &ace_row->header_;
    ace_entries = hmap_count(&ace_header->table->rows);

    /* Updating an ACE always (except comments) creates a new row in ACE table.
     * n_cfg_aces doesn't increment until finish updating ACL table.
     * Abort if ACEs limits are reached */
    if (ace_entries > max_aces) {
        vty_out(vty, "%% Unable to create ACL entry. "
                "The maximum allowed number of ACL entries has been reached%s", VTY_NEWLINE);
        return CMD_ERR_NOTHING_TODO;
    } else if (acl_row->n_cfg_aces >= max_aces_per_acl) {
        vty_out(vty, "%% Unable to create ACL entry. "
                "The maximum allowed number of entries per acl has been reached%s", VTY_NEWLINE);
        return CMD_ERR_NOTHING_TODO;
    } else {
        return CMD_SUCCESS;
    }
}

/**
 * Print an ACL's configuration as if it were entered into the CLI
 *
 * @param acl_row Pointer to ACL row
 *
 * @sa show_run_access_list_callback A similar function that uses a different
 *                                   print method
 */
static void
print_acl_config(const struct ovsrec_acl *acl_row)
{
    char *ace_str;
    int i;

    /* Print ACL command, type, name */
    vty_out(vty,
            "%s %s %s%s",
            "access-list",
            "ip",
            acl_row->name,
            VTY_NEWLINE);

    /* Print each ACL entry as a single line (ala CLI input) */
    for (i = 0; i < acl_row->n_cur_aces; i ++) {
        /* If entry has or is a comment, print as its own line */
        if (acl_row->value_cur_aces[i]->comment) {
            vty_out(vty,
                    "    %" PRId64 " comment %s%s",
                    acl_row->key_cur_aces[i],
                    acl_row->value_cur_aces[i]->comment,
                    VTY_NEWLINE);
        }
        if (acl_row->value_cur_aces[i]->action) {
            ace_str = acl_entry_config_to_string(acl_row->key_cur_aces[i],
                                                 acl_row->value_cur_aces[i]);
            vty_out(vty, "    %s%s", ace_str, VTY_NEWLINE);
            free(ace_str);
        }
    }
}

/**
 * Print header for ACL(s) to be printed in a tabular format
 */
static void
print_acl_tabular_header(void)
{
    vty_out(vty,
            "%-10s %-31s %-18s\n"
             "%10s %-31s %-18s\n"
             "%10s %-31s %-18s\n"
             "%10s %-31s %-18s\n"
             "%10s %-31s %-18s\n"
             "%10s %-31s %-18s%s",
            "Type", "Name", "",
            "Sequence", "Comment", "",
            "", "Action", "L3 Protocol",
            "", "Source IP Address", "Source L4 Port(s)",
            "", "Destination IP Address", "Destination L4 Port(s)",
            "", "Additional Parameters", "", VTY_NEWLINE);
}

/**
 * Print horizontal rule line to separate tabular output
 */
static void
print_acl_horizontal_rule(void)
{
    vty_out(vty, "%s%s",
        "-------------------------------------------------------------------------------",
        VTY_NEWLINE);
}

/**
 * Print human-readable IP Address string
 *
 * The database stores only in dotted-slash notation, but this should be
 * translated to other CLI-style keywords/formats to improve readability.
 *
 * @param format       Format string (e.g. "%s" for simple usage)
 * @param address_str  Pointer to IP address string
 */
static void
print_ace_pretty_ip_address(const char *format, char *address_str)
{
    char user_str[INET_ADDRSTRLEN*2];
    if (acl_ipv4_address_normalized_to_user(address_str, user_str))
    {
        vty_out(vty, format, user_str);
    }
}

/**
 * Print human-readable L4 ports string
 *
 * @param min      First port number
 * @param max      Last port number
 * @param reverse  Whether range is reversed
 */
static void
print_ace_pretty_l4_ports(int64_t min, int64_t max, bool reverse)
{
    if (min == max) {
        if (reverse) {
            vty_out(vty, "%s %5" PRId64, "!=", min);
        } else {
            vty_out(vty, "%s %5" PRId64, " =", min);
        }
    } else if (min == 0 && max < 65535) {
        vty_out(vty, "%s %5" PRId64, " <", max + 1);
    } else if (min > 0 && max == 65535) {
        vty_out(vty, "%s %5" PRId64, " >", min - 1);
    } else {
        vty_out(vty, "%s %5" PRId64 " %s %5" PRId64, "  ", min, "-", max);
    }
}

/**
 * Print an ACL's configuration in a tabular format
 *
 * This function isn't pretty, but this is the only place this formatting style
 * is used, so there's not a lot of re-use to be gained by breaking it up now.
 *
 * @param acl_row Pointer to ACL to print
 */
static void
print_acl_tabular(const struct ovsrec_acl *acl_row)
{
    int i;

    /* Print ACL type and name */
    if (!strcmp(acl_row->list_type, "ipv4")) {
        vty_out(vty, "%-10s ", "IPv4");
    }
    vty_out(vty, "%s%s", acl_row->name, VTY_NEWLINE);

    /* Print each ACL entry as a single line (ala CLI input) */
    for (i = 0; i < acl_row->n_cur_aces; i ++) {
        /* Entry sequence number, action, and protocol (if any) */
        vty_out(vty, "%10" PRId64 " ", acl_row->key_cur_aces[i]);
        /* Comment (if any) */
        if (acl_row->value_cur_aces[i]->comment) {
            vty_out(vty, "%s", acl_row->value_cur_aces[i]->comment);
        }
        if (acl_row->value_cur_aces[i]->action) {
            /* Adjust spacing if a comment was printed as first line */
            if (acl_row->value_cur_aces[i]->comment) {
                vty_out(vty, "%s", VTY_NEWLINE);
                vty_out(vty, "%-10s ", "");
            }
            vty_out(vty, "%-31s ", acl_row->value_cur_aces[i]->action);
        } else {
            vty_out(vty, "%-31s ", "");
        }
        if (acl_row->value_cur_aces[i]->n_protocol != 0) {
            vty_out(vty, "%s ", acl_parse_protocol_get_name_from_number(acl_row->value_cur_aces[i]->protocol[0]));
        } else {
            vty_out(vty, "%s ", "");
        }
        vty_out(vty, "%s", VTY_NEWLINE);
        /* Source IP, port information */
        if (acl_row->value_cur_aces[i]->src_ip) {
            vty_out(vty, "%-10s ", "");
            print_ace_pretty_ip_address("%-31s ", acl_row->value_cur_aces[i]->src_ip);
            if (acl_row->value_cur_aces[i]->n_src_l4_port_min &&
                    acl_row->value_cur_aces[i]->n_src_l4_port_max) {
                print_ace_pretty_l4_ports(
                        acl_row->value_cur_aces[i]->src_l4_port_min[0],
                        acl_row->value_cur_aces[i]->src_l4_port_max[0],
                        acl_row->value_cur_aces[i]->n_src_l4_port_range_reverse);
            }
            vty_out(vty, "%s", VTY_NEWLINE);
        }
        /* Destination IP, port information */
        if (acl_row->value_cur_aces[i]->dst_ip) {
            vty_out(vty, "%-10s ", "");
            print_ace_pretty_ip_address("%-31s ", acl_row->value_cur_aces[i]->dst_ip);
            if (acl_row->value_cur_aces[i]->n_dst_l4_port_min &&
                    acl_row->value_cur_aces[i]->n_dst_l4_port_max) {
                print_ace_pretty_l4_ports(
                        acl_row->value_cur_aces[i]->dst_l4_port_min[0],
                        acl_row->value_cur_aces[i]->dst_l4_port_max[0],
                        acl_row->value_cur_aces[i]->n_dst_l4_port_range_reverse);
            }
            vty_out(vty, "%s", VTY_NEWLINE);
        }
        /* Additional parameters, each on their own line */
        if (acl_row->value_cur_aces[i]->n_log) {
            vty_out(vty, "%-10s Logging: enabled %s", "", VTY_NEWLINE);
        }
        if (acl_row->value_cur_aces[i]->n_count) {
            vty_out(vty, "%-10s Hit-counts: enabled %s", "", VTY_NEWLINE);
        }
    }
}

/**
 * Print information about ACL(s) in specified format
 *
 * @param  acl_type  ACL type string
 * @param  acl_name  ACL name string
 * @param  config    Print as configuration input?
 *
 * @retval CMD_SUCCESS           on success
 * @retval CMD_OVSDB_FAILURE     on database/transaction failure
 * @retval CMD_ERR_NOTHING_TODO  on bad parameter/value
 */
static int
cli_print_acls(const char *acl_type,
               const char *acl_name,
               const char *config)
{
    const struct ovsrec_system *ovs;
    const struct ovsrec_acl *acl_row;

    /* Get System table */
    ovs = ovsrec_system_first(idl);
    if (!ovs) {
        assert(0);
        return CMD_OVSDB_FAILURE;
    }

    /* ACL specified, print just one */
    if (acl_type && acl_name) {
        acl_row = get_acl_by_type_name(acl_type, acl_name);
        if (!acl_row) {
            vty_out(vty, "%% ACL does not exist%s", VTY_NEWLINE);
            return CMD_ERR_NOTHING_TODO;
        }
        if (!config) {
            print_acl_tabular_header();
            print_acl_horizontal_rule();
            print_acl_tabular(acl_row);
        } else {
            print_acl_config(acl_row);
        }
    /* Print all ACLs */
    } else {
        if (!config && ovs->n_acls) {
            print_acl_tabular_header();
            OVSREC_ACL_FOR_EACH(acl_row, idl) {
                print_acl_horizontal_rule();
                print_acl_tabular(acl_row);
            }
            print_acl_horizontal_rule();
        } else {
            OVSREC_ACL_FOR_EACH(acl_row, idl) {
                print_acl_config(acl_row);
            }
        }
    }

    return CMD_SUCCESS;
}

/**
 * Create an ACL if it does not exist
 *
 * @param  acl_type  ACL type string
 * @param  acl_name  ACL name string
 *
 * @retval CMD_SUCCESS           on success
 * @retval CMD_OVSDB_FAILURE     on database/transaction failure
 * @retval CMD_ERR_NOTHING_TODO  on bad parameter/value
 */
static int
cli_create_acl_if_needed(const char *acl_type, const char *acl_name)
{
    struct ovsdb_idl_txn *transaction;
    enum ovsdb_idl_txn_status txn_status;
    const struct ovsrec_system *ovs;
    const struct ovsrec_acl *acl_row;
    const struct ovsrec_acl **acl_info;
    int i;

    /* Start transaction */
    transaction = cli_do_config_start();
    if (!transaction) {
        VLOG_ERR("Unable to acquire transaction");
        return CMD_OVSDB_FAILURE;
    }

    /* Get System table */
    ovs = ovsrec_system_first(idl);
    if (!ovs) {
        cli_do_config_abort(transaction);
        assert(0);
        return CMD_OVSDB_FAILURE;
    }

    /* Get ACL row */
    acl_row = get_acl_by_type_name(acl_type, acl_name);

    /* Create */
    if (!acl_row) {
        const char* max_acls_str;
        int64_t max_acls;

        /* Get max ACLs from system table, other config */
        max_acls_str = smap_get(&ovs->other_config, "max_acls");

        if (max_acls_str) {
            max_acls = strtol(max_acls_str, NULL, 0);
        } else {
            cli_do_config_abort(transaction);
            VLOG_ERR("Unable to acquire ACL hardware limits.");
            return CMD_OVSDB_FAILURE;
        }

        /* Abort if hardware limit is reached */
        if (ovs->n_acls >= max_acls) {
            vty_out(vty, "%% Unable to create ACL. "
                    "The maximum allowed number of ACLs has been reached%s", VTY_NEWLINE);
            cli_do_config_abort(transaction);
            return CMD_SUCCESS;
        }
        VLOG_DBG("Creating ACL type=%s name=%s", acl_type, acl_name);

        /* Create, populate new ACL table row */
        acl_row = ovsrec_acl_insert(transaction);
        ovsrec_acl_set_list_type(acl_row, acl_type);
        ovsrec_acl_set_name(acl_row, acl_name);
        ovsrec_acl_set_cfg_version(acl_row, 0);

        /* Update System (parent) table */
        acl_info = xmalloc(sizeof *ovs->acls * (ovs->n_acls + 1));
        for (i = 0; i < ovs->n_acls; i++) {
            acl_info[i] = ovs->acls[i];
        }
        acl_info[i] = acl_row;
        ovsrec_system_set_acls(ovs, (struct ovsrec_acl **) acl_info, i + 1);
        free(acl_info);
    }
    /* Update */
    else {
        VLOG_DBG("Updating ACL type=%s name=%s", acl_type, acl_name);

        /* Don't actually have to take any action */
    }

    /* Complete transaction */
    txn_status = cli_do_config_finish(transaction);
    if (txn_status == TXN_SUCCESS || txn_status == TXN_UNCHANGED) {
        return CMD_SUCCESS;
    } else {
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }
}

/**
 * Delete an ACL
 *
 * @param  acl_type  ACL type string
 * @param  acl_name  ACL name string
 *
 * @retval CMD_SUCCESS           on success
 * @retval CMD_OVSDB_FAILURE     on database/transaction failure
 * @retval CMD_ERR_NOTHING_TODO  on bad parameter/value
 *
 */
static int
cli_delete_acl(const char *acl_type, const char *acl_name)
{
    struct ovsdb_idl_txn *transaction;
    enum ovsdb_idl_txn_status txn_status;
    const struct ovsrec_system *ovs;
    const struct ovsrec_acl *acl_row;
    const struct ovsrec_acl **acl_info;
    int i, n;

    /* Start transaction */
    transaction = cli_do_config_start();
    if (!transaction) {
        VLOG_ERR("Unable to acquire transaction");
        return CMD_OVSDB_FAILURE;
    }

    /* Get System table */
    ovs = ovsrec_system_first(idl);
    if (!ovs) {
        cli_do_config_abort(transaction);
        assert(0);
        return CMD_OVSDB_FAILURE;
    }

    /* Get ACL row */
    acl_row = get_acl_by_type_name(acl_type, acl_name);

    /* ACL exists, delete it */
    if (acl_row) {
        VLOG_DBG("Deleting ACL type=%s name=%s", acl_type, acl_name);

        /* Remove ACL row */
        ovsrec_acl_delete(acl_row);

        /* Update System table */
        acl_info = xmalloc(sizeof *ovs->acls * (ovs->n_acls - 1));
        for (i = n = 0; i < ovs->n_acls; i++) {
            if (ovs->acls[i] != acl_row) {
                acl_info[n++] = ovs->acls[i];
            }
        }
        ovsrec_system_set_acls(ovs, (struct ovsrec_acl **) acl_info, n);
        free(acl_info);
    }
    /* No such ACL exists */
    else {
        vty_out(vty, "%% ACL does not exist%s", VTY_NEWLINE);
        cli_do_config_abort(transaction);
        return CMD_ERR_NOTHING_TODO;
    }

    /* Complete transaction */
    txn_status = cli_do_config_finish(transaction);
    if (txn_status == TXN_SUCCESS || txn_status == TXN_UNCHANGED) {
        return CMD_SUCCESS;
    } else {
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }
}

/**
 * Wait for an ACL matching the given type and name to have a status for the
 * given configuration version.
 *
 * @param  acl_type             Type string
 * @param  acl_name             Name string
 * @param  pending_cfg_version  Configuration version to wait for status on
 *
 * @retval CMD_SUCCESS on success
 * @retval CMD_WARNING if the operation may not have succeeded
 *
 * @todo use a timer to avoid waiting forever if ops-switchd is gone
 * @todo allow ctrl-c to interrupt waiting
 */
static int
wait_for_ace_update_status(const char *acl_type,
                           const char *acl_name,
                           const int64_t pending_cfg_version)
{
    const struct ovsrec_acl *acl_row;
    int64_t status_version;
    const char *status_version_str;
    const char *status_state_str;
    const char *status_message_str;
    const char *status_code_str;

    while (true) {
        /* Let OVSDB IDL update thread run */
        VTYSH_OVSDB_UNLOCK;
        /* Set latch to wake up OVSDB thread and get new status */
        latch_set(&ovsdb_latch);
        /* Take lock so we can safely operate on IDL again */
        VTYSH_OVSDB_LOCK;
        /* We purposely return with OVSDB lock held below because execute_command unlocks */
        acl_row = get_acl_by_type_name(acl_type, acl_name);
        status_version_str = smap_get(&acl_row->status, OPS_CLS_STATUS_VERSION_STR);
        if (status_version_str) {
            status_version = strtoull(status_version_str, NULL, 0);
            /* We got a status for the version we configured */
            if (status_version == pending_cfg_version) {
                status_state_str = smap_get(&acl_row->status, OPS_CLS_STATUS_STATE_STR);
                if (!strcmp(status_state_str, OPS_CLS_STATE_APPLIED_STR)) {
                    return CMD_SUCCESS;
                } else {
                    status_message_str = smap_get(&acl_row->status, OPS_CLS_STATUS_MSG_STR);
                    status_code_str = smap_get(&acl_row->status, OPS_CLS_STATUS_CODE_STR);
                    vty_out(vty, "%% Configuration %s: %s (code %s)%s",
                            status_state_str ? status_state_str : "(no state)",
                            status_message_str ? status_message_str : "(no message)",
                            status_code_str ? status_code_str : "none",
                            VTY_NEWLINE);
                    return CMD_WARNING;
                }
            /* We got a status for a later configuration version */
            } else if (status_version > pending_cfg_version) {
                vty_out(vty, "%% Other changes may have occurred while this change was being processed%s", VTY_NEWLINE);
                return CMD_WARNING;
            }
        }
    }
}

/**
 * Create/Update an ACE
 *
 * @param  acl_type                       Type string
 * @param  acl_name                       Name string
 * @param  ace_sequence_number_str        Sequence number string (NULL = auto)
 * @param  ace_action                     Action string
 * @param  ace_ip_protocol                IP protocol string
 * @param  ace_source_ip_address          Source IP address string
 * @param  ace_source_port_operator       Operator for source port(s)
 * @param  ace_source_port                First source port
 * @param  ace_source_port_max            Second source port (range only)
 * @param  ace_destination_ip_address     Destination IP address string
 * @param  ace_destination_port_operator  Operator for destination port(s)
 * @param  ace_destination_port           First destination port
 * @param  ace_destination_port_max       Second destination port (range only)
 * @param  ace_log_enabled                Is logging enabled on this entry?
 * @param  ace_count_enabled              Is counting enabled on this entry?
 * @param  ace_comment                    Text comment string (must be freed)
 *
 * @retval CMD_SUCCESS           on success
 * @retval CMD_OVSDB_FAILURE     on database/transaction failure
 * @retval CMD_ERR_NOTHING_TODO  on bad parameter/value
 */
static int
cli_create_update_ace (const char *acl_type,
                       const char *acl_name,
                       const char *ace_sequence_number_str,
                       const char *ace_action,
                       const char *ace_ip_protocol,
                       const char *ace_source_ip_address,
                       const char *ace_source_port_operator,
                       const char *ace_source_port,
                       const char *ace_source_port_max,
                       const char *ace_destination_ip_address,
                       const char *ace_destination_port_operator,
                       const char *ace_destination_port,
                       const char *ace_destination_port_max,
                       const char *ace_log_enabled,
                       const char *ace_count_enabled,
                             char *ace_comment)
{
    struct ovsdb_idl_txn *transaction;
    enum ovsdb_idl_txn_status txn_status;
    const struct ovsrec_acl *acl_row;
    const struct ovsrec_acl_entry *old_ace_row, *ace_row;
    int64_t ace_sequence_number;
    int64_t protocol_num, min_num, max_num;
    char addr_str[INET_ADDRSTRLEN*2];
    bool flag;
    int64_t pending_cfg_version;

    VLOG_DBG("Create/Update");

    /* Start transaction */
    transaction = cli_do_config_start();
    if (!transaction) {
        VLOG_ERR("Unable to acquire transaction");
        return CMD_OVSDB_FAILURE;
    }

    /* Get parent ACL row */
    acl_row = get_acl_by_type_name(acl_type, acl_name);
    if (!acl_row) {
        /* Should not be possible; context should have created if needed */
        vty_out(vty, "%% ACL does not exist%s", VTY_NEWLINE);
        cli_do_config_abort(transaction);
        return CMD_ERR_NOTHING_TODO;
    }

    /* If a sequence number is specified, use it */
    if (ace_sequence_number_str) {
        ace_sequence_number = strtoll(ace_sequence_number_str, NULL, 0);
    /* Otherwise set sequence number to the current highest + auto-increment */
    } else {
        int64_t highest_ace_seq = 0;
        if (acl_row->n_cur_aces > 0) {
            /* ACEs are stored sorted, so just get the last one */
            highest_ace_seq = acl_row->key_cur_aces[acl_row->n_cur_aces - 1];
        }
        if (highest_ace_seq + ACE_SEQ_AUTO_INCR > ACE_SEQ_MAX) {
            vty_out(vty, "%% Unable to automatically set sequence number%s", VTY_NEWLINE);
            cli_do_config_abort(transaction);
            return CMD_ERR_NOTHING_TODO;
        }
        ace_sequence_number = highest_ace_seq + ACE_SEQ_AUTO_INCR;
    }

    /* Create new, empty ACE table row (garbage collected if unused) */
    ace_row = ovsrec_acl_entry_insert(transaction);
    if (!ace_row)
    {
        vty_out(vty, "%% Unable to add ACL entry%s", VTY_NEWLINE);
        cli_do_config_abort(transaction);
        return CMD_OVSDB_FAILURE;
    }

    /* Updating an ACE always (except comments) creates a new row.
       If the old ACE is no longer referenced it will be garbage-collected. */
    old_ace_row = ovsrec_acl_cur_aces_getvalue(acl_row, ace_sequence_number);
    if (old_ace_row) {
        VLOG_DBG("Updating ACE seq=%" PRId64, ace_sequence_number);

        /* Comment applied to existing entry */
        if (!strcmp(ace_action, "comment")) {
            /* May set to NULL if action is comment and text is empty (remove) */
            ovsrec_acl_entry_set_comment(old_ace_row, ace_comment);
            if (ace_comment) {
                free(ace_comment);
            }
            /* Complete transaction */
            txn_status = cli_do_config_finish(transaction);
            if (txn_status == TXN_SUCCESS || txn_status == TXN_UNCHANGED) {
                return CMD_SUCCESS;
            } else {
                VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
                return CMD_OVSDB_FAILURE;
            }
        /* Copy comment (if any) from old entry  */
        } else {
            ovsrec_acl_entry_set_comment(ace_row, old_ace_row->comment);
        }
    } else {
        int result;
        /* Check ACEs capacity */
        result = check_ace_capacity(acl_row, ace_row);
        if (CMD_SUCCESS != result) {
          cli_do_config_abort(transaction);
          /* Error message is logged in check_ace_capacity */
          return result;
        }
        VLOG_DBG("Creating ACE seq=%" PRId64, ace_sequence_number);
    }

    /* Set any updated columns */
    if (ace_action) {
        if (!strcmp(ace_action, "permit") || !strcmp(ace_action, "deny")) {
            ovsrec_acl_entry_set_action(ace_row, ace_action);
        }
    }
    if (ace_ip_protocol) {
        if (acl_parse_str_is_numeric(ace_ip_protocol)) {
            protocol_num = strtoll(ace_ip_protocol, NULL, 0);
        } else {
            protocol_num = acl_parse_protocol_get_number_from_name(ace_ip_protocol);
        }
        ovsrec_acl_entry_set_protocol(ace_row, &protocol_num, 1);
    }
    if (ace_source_ip_address) {
        if (acl_ipv4_address_user_to_normalized(ace_source_ip_address, addr_str)) {
            ovsrec_acl_entry_set_src_ip(ace_row, addr_str);
        } else {
            vty_out(vty, "%% Invalid source IP address%s", VTY_NEWLINE);
            cli_do_config_abort(transaction);
            return CMD_ERR_NOTHING_TODO;
        }
    }
    if (ace_source_port_operator) {
        if (!strcmp(ace_source_port_operator, "eq")) {
            min_num = strtoll(ace_source_port, NULL, 0);
            ovsrec_acl_entry_set_src_l4_port_min(ace_row, &min_num, 1);
            ovsrec_acl_entry_set_src_l4_port_max(ace_row, &min_num, 1);
        } else if (!strcmp(ace_source_port_operator, "neq")) {
            flag = true;
            min_num = strtoll(ace_source_port, NULL, 0);
            ovsrec_acl_entry_set_src_l4_port_min(ace_row, &min_num, 1);
            ovsrec_acl_entry_set_src_l4_port_max(ace_row, &min_num, 1);
            ovsrec_acl_entry_set_src_l4_port_range_reverse(ace_row, &flag, 1);
        } else if (!strcmp(ace_source_port_operator, "gt")) {
            min_num = strtoll(ace_source_port, NULL, 0) + 1;
            max_num = 65535;
            if (min_num > max_num) {
                vty_out(vty, "%% Invalid L4 source port%s", VTY_NEWLINE);
                cli_do_config_abort(transaction);
                return CMD_ERR_NOTHING_TODO;
            }
            ovsrec_acl_entry_set_src_l4_port_min(ace_row, &min_num, 1);
            ovsrec_acl_entry_set_src_l4_port_max(ace_row, &max_num, 1);
        } else if (!strcmp(ace_source_port_operator, "lt")) {
            min_num = 0;
            max_num = strtoll(ace_source_port, NULL, 0) - 1;
            if (min_num > max_num) {
                vty_out(vty, "%% Invalid L4 source port%s", VTY_NEWLINE);
                cli_do_config_abort(transaction);
                return CMD_ERR_NOTHING_TODO;
            }
            ovsrec_acl_entry_set_src_l4_port_min(ace_row, &min_num, 1);
            ovsrec_acl_entry_set_src_l4_port_max(ace_row, &max_num, 1);
        } else if (!strcmp(ace_source_port_operator, "range")) {
            min_num = strtoll(ace_source_port, NULL, 0);
            max_num = strtoll(ace_source_port_max, NULL, 0);
            if (min_num > max_num) {
                vty_out(vty, "%% Invalid L4 source port range%s", VTY_NEWLINE);
                cli_do_config_abort(transaction);
                return CMD_ERR_NOTHING_TODO;
            }
            ovsrec_acl_entry_set_src_l4_port_min(ace_row, &min_num, 1);
            ovsrec_acl_entry_set_src_l4_port_max(ace_row, &max_num, 1);
        }
    }
    if (ace_destination_ip_address) {
        if (acl_ipv4_address_user_to_normalized(ace_destination_ip_address, addr_str)) {
            ovsrec_acl_entry_set_dst_ip(ace_row, addr_str);
        } else {
            vty_out(vty, "%% Invalid destination IP address%s", VTY_NEWLINE);
            cli_do_config_abort(transaction);
            return CMD_ERR_NOTHING_TODO;
        }
    }
    if (ace_destination_port_operator) {
        if (!strcmp(ace_destination_port_operator, "eq")) {
            min_num = strtoll(ace_destination_port, NULL, 0);
            ovsrec_acl_entry_set_dst_l4_port_min(ace_row, &min_num, 1);
            ovsrec_acl_entry_set_dst_l4_port_max(ace_row, &min_num, 1);
        } else if (!strcmp(ace_destination_port_operator, "neq")) {
            flag = true;
            min_num = strtoll(ace_destination_port, NULL, 0);
            ovsrec_acl_entry_set_dst_l4_port_min(ace_row, &min_num, 1);
            ovsrec_acl_entry_set_dst_l4_port_max(ace_row, &min_num, 1);
            ovsrec_acl_entry_set_dst_l4_port_range_reverse(ace_row, &flag, 1);
        } else if (!strcmp(ace_destination_port_operator, "gt")) {
            min_num = strtoll(ace_destination_port, NULL, 0) + 1;
            max_num = 65535;
            if (min_num > max_num) {
                vty_out(vty, "%% Invalid L4 destination port%s", VTY_NEWLINE);
                cli_do_config_abort(transaction);
                return CMD_ERR_NOTHING_TODO;
            }
            ovsrec_acl_entry_set_dst_l4_port_min(ace_row, &min_num, 1);
            ovsrec_acl_entry_set_dst_l4_port_max(ace_row, &max_num, 1);
        } else if (!strcmp(ace_destination_port_operator, "lt")) {
            min_num = 0;
            max_num = strtoll(ace_destination_port, NULL, 0) - 1;
            if (min_num > max_num) {
                vty_out(vty, "%% Invalid L4 destination port%s", VTY_NEWLINE);
                cli_do_config_abort(transaction);
                return CMD_ERR_NOTHING_TODO;
            }
            ovsrec_acl_entry_set_dst_l4_port_min(ace_row, &min_num, 1);
            ovsrec_acl_entry_set_dst_l4_port_max(ace_row, &max_num, 1);
        } else if (!strcmp(ace_destination_port_operator, "range")) {
            min_num = strtoll(ace_destination_port, NULL, 0);
            max_num = strtoll(ace_destination_port_max, NULL, 0);
            if (min_num > max_num) {
                vty_out(vty, "%% Invalid L4 destination port range%s", VTY_NEWLINE);
                cli_do_config_abort(transaction);
                return CMD_ERR_NOTHING_TODO;
            }
            ovsrec_acl_entry_set_dst_l4_port_min(ace_row, &min_num, 1);
            ovsrec_acl_entry_set_dst_l4_port_max(ace_row, &max_num, 1);
        }
    }
    if (ace_log_enabled) {
        flag = true;
        ovsrec_acl_entry_set_log(ace_row, &flag, 1);
        /* Enabling log implies enabling hit counts */
        ovsrec_acl_entry_set_count(ace_row, &flag, 1);
    }
    if (ace_count_enabled) {
        flag = true;
        ovsrec_acl_entry_set_count(ace_row, &flag, 1);
    }
    /* New entry with only a comment */
    if (ace_comment) {
        ovsrec_acl_entry_set_comment(ace_row, ace_comment);
        free(ace_comment);
    }

    /* Update ACL (parent) table */
    ovsrec_acl_set_cfg_aces_from_cur_aces(acl_row, ace_sequence_number, (struct ovsrec_acl_entry *) ace_row);
    pending_cfg_version = acl_row->cfg_version + 1;
    ovsrec_acl_set_cfg_version(acl_row, pending_cfg_version);

    /* Complete transaction */
    txn_status = cli_do_config_finish(transaction);
    if (txn_status != TXN_SUCCESS && txn_status != TXN_UNCHANGED) {
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }

    /* Wait until ACE update either succeeds or fails and report to user */
    return wait_for_ace_update_status(acl_type, acl_name, pending_cfg_version);
}

/**
 * Delete an ACE
 *
 * @param  acl_type                 ACL type string
 * @param  acl_name                 ACL name string
 * @param  ace_sequence_number_str  ACE parameter string
 *
 * @retval CMD_SUCCESS           on success
 * @retval CMD_OVSDB_FAILURE     on database/transaction failure
 * @retval CMD_ERR_NOTHING_TODO  on bad parameter/value
 *
 */
static int
cli_delete_ace (const char *acl_type,
                const char *acl_name,
                const char *ace_sequence_number_str)
{
    struct ovsdb_idl_txn *transaction;
    enum ovsdb_idl_txn_status txn_status;
    const struct ovsrec_acl *acl_row;
    int64_t ace_sequence_number;
    int64_t pending_cfg_version;

    /* Start transaction */
    transaction = cli_do_config_start();
    if (!transaction) {
        VLOG_ERR("Unable to acquire transaction");
        return CMD_OVSDB_FAILURE;
    }

    /* Get parent ACL row */
    acl_row = get_acl_by_type_name(acl_type, acl_name);
    if (!acl_row) {
        /* Should not be possible; context should have created */
        vty_out(vty, "%% ACL does not exist%s", VTY_NEWLINE);
        cli_do_config_abort(transaction);
        return CMD_ERR_NOTHING_TODO;
    }

    /* Should already be guarded against by parser */
    if (!ace_sequence_number_str) {
        vty_out(vty, "%% Invalid sequence number%s", VTY_NEWLINE);
        cli_do_config_abort(transaction);
        return CMD_ERR_NOTHING_TODO;
    }
    ace_sequence_number = strtoll(ace_sequence_number_str, NULL, 0);

    /* Check to make sure ACE is present in ACL */

    VLOG_DBG("Deleting ACE seq=%" PRId64, ace_sequence_number);
    if (!ovsrec_acl_set_cfg_aces_from_cur_aces(acl_row, ace_sequence_number, NULL)) {
        vty_out(vty, "%% ACL entry does not exist%s", VTY_NEWLINE);
        cli_do_config_abort(transaction);
        return CMD_ERR_NOTHING_TODO;
    }
    pending_cfg_version = acl_row->cfg_version + 1;
    ovsrec_acl_set_cfg_version(acl_row, pending_cfg_version);
    /* If ACE is no longer referenced it will be garbage-collected */

    /* Complete transaction */
    txn_status = cli_do_config_finish(transaction);
    if (txn_status == TXN_SUCCESS || txn_status == TXN_UNCHANGED) {
        return CMD_SUCCESS;
    } else {
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }

    /* Wait until ACE update either succeeds or fails and report to user */
    return wait_for_ace_update_status(acl_type, acl_name, pending_cfg_version);
}

/**
 * Resequence entries in an ACL
 *
 * @param  acl_type   ACL type string
 * @param  acl_name   ACL string name to apply
 * @param  start      Starting entry sequence number
 * @param  increment  Increment to increase each entry's sequence number by
 *
 * @retval CMD_SUCCESS           on success
 * @retval CMD_OVSDB_FAILURE     on database/transaction failure
 * @retval CMD_ERR_NOTHING_TODO  on bad parameter/value
 */
static int
cli_resequence_acl (const char *acl_type,
                    const char *acl_name,
                    const char *start,
                    const char *increment)
{
    struct ovsdb_idl_txn *transaction;
    enum ovsdb_idl_txn_status txn_status;
    const struct ovsrec_acl *acl_row;
    unsigned long start_num, increment_num, current_num;
    int64_t *key_list;
    struct ovsrec_acl_entry **value_list;
    int i;
    int64_t pending_cfg_version;

    /* Start transaction */
    transaction = cli_do_config_start();
    if (!transaction) {
        VLOG_ERR("Unable to acquire transaction");
        return CMD_OVSDB_FAILURE;
    }

    /* Get ACL row */
    acl_row = get_acl_by_type_name(acl_type, acl_name);
    if (!acl_row) {
        vty_out(vty, "%% ACL does not exist%s", VTY_NEWLINE);
        cli_do_config_abort(transaction);
        return CMD_ERR_NOTHING_TODO;
    }

    /* Check for an empty list */
    if (!acl_row->n_cur_aces) {
        vty_out(vty, "%% ACL is empty%s", VTY_NEWLINE);
        cli_do_config_abort(transaction);
        return CMD_ERR_NOTHING_TODO;
    }

    /* Set numeric values */
    start_num = strtoul(start, NULL, 0);
    increment_num = strtoul(increment, NULL, 0);
    current_num = start_num;

    /* Check that sequence numbers will not exceed maximum a_n = a_0 + (n-1)d
     * Test that formula works for ACE_SEQ_MAX of 4294967295:
     *   use start = 3, increment = 1073741823 on 5-ACE list
     *   input should be accepted
     *   resequence should result in ACE #5 seq=4294967295
     */
    if (start_num + ((acl_row->n_cur_aces - 1) * increment_num) > ACE_SEQ_MAX) {
        vty_out(vty, "%% Sequence numbers would exceed maximum%s", VTY_NEWLINE);
        cli_do_config_abort(transaction);
        return CMD_ERR_NOTHING_TODO;
    }

    /* Initialize temporary data structures */
    key_list = xmalloc(sizeof(int64_t) * (acl_row->n_cur_aces));
    value_list = xmalloc(sizeof *acl_row->value_cur_aces * (acl_row->n_cur_aces));

    /* Walk through sorted list, resequencing by adding into new_aces */
    for (i = 0; i < acl_row->n_cur_aces; i++) {
        key_list[i] = current_num;
        value_list[i] = acl_row->value_cur_aces[i];
        current_num += increment_num;
    }

    /* Replace ACL's entries with resequenced ones */
    ovsrec_acl_set_cfg_aces(acl_row, key_list, value_list, acl_row->n_cur_aces);
    pending_cfg_version = acl_row->cfg_version + 1;
    ovsrec_acl_set_cfg_version(acl_row, pending_cfg_version);

    /* Clean up temporary data structures */
    free(key_list);
    free(value_list);

    /* Complete transaction */
    txn_status = cli_do_config_finish(transaction);
    if (txn_status == TXN_SUCCESS || txn_status == TXN_UNCHANGED) {
        return CMD_SUCCESS;
    } else {
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }

    /* Wait until ACE update either succeeds or fails and report to user */
    return wait_for_ace_update_status(acl_type, acl_name, pending_cfg_version);
}

/**
 * Display ACLs applied to the specified interface in the given direction
 *
 * @param  interface_type  Interface (Port/VLAN) type string
 * @param  interface_id    Interface (Port/VLAN) identifier string
 * @param  acl_type        ACL type string
 * @param  direction       Direction of traffic ACL is applied to
 * @param  config          Print as configuration input?
 *
 * @retval CMD_SUCCESS           on success
 * @retval CMD_OVSDB_FAILURE     on database/transaction failure
 * @retval CMD_ERR_NOTHING_TODO  on bad parameter/value
 */
static int
cli_print_applied_acls (const char *interface_type,
                        const char *interface_id,
                        const char *acl_type,
                        const char *direction,
                        const char *config)
{
    /* Port (unfortunately called "interface" in the CLI) */
    if (!strcmp(interface_type, "interface")) {
        const struct ovsrec_port *port_row;

        /* Get Port row */
        port_row = get_port_by_name(interface_id);
        if (!port_row) {
            vty_out(vty, "%% Port does not exist%s", VTY_NEWLINE);
            return CMD_ERR_NOTHING_TODO;
        }

        if (port_row->aclv4_in_applied) {
            VLOG_DBG("Found ACL application port=%s name=%s",
                     interface_id, port_row->aclv4_in_applied->name);
            if (config)
            {
                print_acl_config(port_row->aclv4_in_applied);
            } else {
                vty_out(vty, "%-10s %-31s%s", "Direction", "", VTY_NEWLINE);
                print_acl_tabular_header();
                print_acl_horizontal_rule();
                vty_out(vty, "%-10s %-31s%s", "Inbound", "", VTY_NEWLINE);
                print_acl_tabular(port_row->aclv4_in_applied);
                print_acl_horizontal_rule();
            }
        }

        /* Print application commands if printing config */
        if (config && port_row->aclv4_in_applied) {
            vty_out(vty, "%s %s\n    %s %s %s %s %s%s",
                    "interface", port_row->name,
                    "apply", "access-list", "ip",
                    port_row->aclv4_in_applied->name, "in",
                    VTY_NEWLINE);
        }
    } else if (!strcmp(interface_type, "vlan")) {
        const struct ovsrec_vlan *vlan_row;

        /* Get VLAN row */
        vlan_row = get_vlan_by_id_str(interface_id);
        if (!vlan_row) {
            vty_out(vty, "%% VLAN does not exist%s", VTY_NEWLINE);
            return CMD_ERR_NOTHING_TODO;
        }

        if (vlan_row->aclv4_in_applied) {
            VLOG_DBG("Found ACL application vlan=%s name=%s",
                     interface_id, vlan_row->aclv4_in_applied->name);
            if (config)
            {
                print_acl_config(vlan_row->aclv4_in_applied);
            } else {
                vty_out(vty, "%-10s %-31s%s", "Direction", "", VTY_NEWLINE);
                print_acl_tabular_header();
                print_acl_horizontal_rule();
                vty_out(vty, "%-10s %-31s%s", "Inbound", "", VTY_NEWLINE);
                print_acl_tabular(vlan_row->aclv4_in_applied);
                print_acl_horizontal_rule();
            }
        }

        /* Print application commands if printing config */
        if (config && vlan_row->aclv4_in_applied) {
            vty_out(vty, "%s %" PRId64 "\n    %s %s %s %s %s%s",
                    "vlan", vlan_row->id,
                    "apply", "access-list", "ip",
                    vlan_row->aclv4_in_applied->name, "in",
                    VTY_NEWLINE);
        }
    }

    return CMD_SUCCESS;
}

/**
 * Wait for an inteface (e.g. port or VLAN) matching the given type and ID and
 * ACL type and direction to have a status for the given configuration version.
 *
 * @param  interface_type       Interface (Port/VLAN) type string
 * @param  interface_id         Interface (Port/VLAN) identifier string
 * @param  acl_type             ACL type string
 * @param  direction            Direction of traffic ACL is applied to
 * @param  pending_cfg_version  Configuration version to wait for status on
 *
 * @todo use a timer to avoid waiting forever if ops-switchd is gone
 * @todo allow ctrl-c to interrupt waiting
 */
static int
wait_for_acl_apply_status(const char *interface_type,
                          const char *interface_id,
                          const char *acl_type,
                          const char *direction,
                          const int64_t pending_cfg_version)
{
    const struct ovsrec_port *port_row;
    const struct smap *status_map;
    int64_t status_version;
    const char *status_version_str;
    const char *status_state_str;
    const char *status_message_str;
    const char *status_code_str;

    while (true) {
        /* Let OVSDB IDL update thread run */
        VTYSH_OVSDB_UNLOCK;
        /* Set latch to wake up OVSDB thread and get new status */
        latch_set(&ovsdb_latch);
        /* Take lock so we can safely operate on IDL again */
        VTYSH_OVSDB_LOCK;
        /* We purposely return with OVSDB lock held below because execute_command unlocks */
        /* Port (unfortunately called "interface" in the CLI) */
        if (!strcmp(interface_type, "interface")) {
            port_row = get_port_by_name(interface_id);
            if (!strcmp(acl_type, "ipv4") && !strcmp(direction, "in")) {
                status_map = &port_row->aclv4_in_status;
                status_version_str = smap_get(status_map, OPS_CLS_STATUS_VERSION_STR);
            } else {
                vty_out(vty, "%% Unsupported ACL type or direction%s", VTY_NEWLINE);
                return CMD_WARNING;
            }
        } else if (!strcmp(interface_type, "vlan")) {
            /** @todo Remove once classifier feature plug-in supports VLAN apply. */
            vty_out(vty, "%% warning: VLAN ACLs presently unsupported by classifier feature plug-in%s", VTY_NEWLINE);
            VLOG_WARN("VLAN ACLs presently unsupported by classifier feature plug-in");
            /* Return now because ops-switchd won't update VLAN ACL status
               and we'll wait for no reason until it supports VLAN ACLs. */
            return CMD_WARNING;
        } else {
            vty_out(vty, "%% Unsupported interface type%s", VTY_NEWLINE);
            return CMD_WARNING;
        }
        if (status_version_str) {
            status_version = strtoull(status_version_str, NULL, 0);
            /* We got a status for the version we configured */
            if (status_version == pending_cfg_version) {
                status_state_str = smap_get(status_map, OPS_CLS_STATUS_STATE_STR);
                if (!strcmp(status_state_str, OPS_CLS_STATE_APPLIED_STR)) {
                    return CMD_SUCCESS;
                } else {
                    status_message_str = smap_get(status_map, OPS_CLS_STATUS_MSG_STR);
                    status_code_str = smap_get(status_map, OPS_CLS_STATUS_CODE_STR);
                    vty_out(vty, "%% Configuration %s: %s (code %s)%s",
                            status_state_str ? status_state_str : "(no state)",
                            status_message_str ? status_message_str : "(no message)",
                            status_code_str ? status_code_str : "none",
                            VTY_NEWLINE);
                    return CMD_WARNING;
                }
            /* We got a status for a later configuration version */
            } else if (status_version > pending_cfg_version) {
                vty_out(vty, "%% Other changes may have occurred while this change was being processed%s", VTY_NEWLINE);
                return CMD_WARNING;
            }
        }
    }
}

/**
 * Apply an ACL to an interface in a specified direction
 *
 * @param  interface_type  Interface (Port/VLAN) type string
 * @param  interface_id    Interface (Port/VLAN) identifier string
 * @param  acl_type        ACL type string
 * @param  acl_name        ACL string name to apply
 * @param  direction       Direction of traffic ACL is applied to
 *
 * @retval CMD_SUCCESS           on success
 * @retval CMD_OVSDB_FAILURE     on database/transaction failure
 * @retval CMD_ERR_NOTHING_TODO  on bad parameter/value
 */
static int
cli_apply_acl (const char *interface_type,
               const char *interface_id,
               const char *acl_type,
               const char *acl_name,
               const char *direction)
{
    struct ovsdb_idl_txn *transaction;
    enum ovsdb_idl_txn_status txn_status;
    const struct ovsrec_acl *acl_row;
    int64_t pending_cfg_version;

    VLOG_DBG("Apply");

    /* Start transaction */
    transaction = cli_do_config_start();
    if (!transaction) {
        VLOG_ERR("Unable to acquire transaction");
        return CMD_OVSDB_FAILURE;
    }

    /* Get ACL row */
    acl_row = get_acl_by_type_name(acl_type, acl_name);
    if (!acl_row) {
        vty_out(vty, "%% ACL does not exist%s", VTY_NEWLINE);
        cli_do_config_abort(transaction);
        return CMD_ERR_NOTHING_TODO;
    }

    /* Port (unfortunately called "interface" in the CLI) */
    if (!strcmp(interface_type, "interface")) {
        const struct ovsrec_port *port_row;
        /* Get Port row */
        port_row = get_port_by_name(interface_id);
        if (!port_row) {
            vty_out(vty, "%% Port does not exist%s", VTY_NEWLINE);
            cli_do_config_abort(transaction);
            return CMD_ERR_NOTHING_TODO;
        }

        if (!strcmp(acl_type, "ipv4") && !strcmp(direction, "in")) {
            /* Check if we're replacing an already-applied ACL */
            if (port_row->aclv4_in_applied) {
                VLOG_DBG("Old ACL application port=%s acl_name=%s",
                         interface_id, port_row->aclv4_in_applied->name);
            }
            /* Apply the requested ACL to the Port */
            VLOG_DBG("New ACL application port=%s acl_name=%s", interface_id, acl_name);
            ovsrec_port_set_aclv4_in_cfg(port_row, acl_row);
            if (port_row->n_aclv4_in_cfg_version) {
                pending_cfg_version = port_row->aclv4_in_cfg_version[0] + 1;
            } else {
                pending_cfg_version = 0;
            }
            ovsrec_port_set_aclv4_in_cfg_version(port_row, &pending_cfg_version, 1);
        } else {
            vty_out(vty, "%% Unsupported ACL type or direction%s", VTY_NEWLINE);
            cli_do_config_abort(transaction);
            return CMD_ERR_NOTHING_TODO;
        }

    } else if (!strcmp(interface_type, "vlan")) {

        const struct ovsrec_vlan *vlan_row;
        /* Get VLAN row */
        vlan_row = get_vlan_by_id_str(interface_id);
        if (!vlan_row) {
            vty_out(vty, "%% VLAN does not exist%s", VTY_NEWLINE);
            cli_do_config_abort(transaction);
            return CMD_ERR_NOTHING_TODO;
        }

        if (!strcmp(acl_type, "ipv4") && !strcmp(direction, "in")) {
            /* Check if we're replacing an already-applied ACL */
            if (vlan_row->aclv4_in_applied) {
                VLOG_DBG("Old ACL application vlan=%s acl_name=%s",
                         interface_id, vlan_row->aclv4_in_applied->name);
            }

            /* Apply the requested ACL to the VLAN */
            VLOG_DBG("New ACL application vlan=%s acl_name=%s", interface_id, acl_name);
            ovsrec_vlan_set_aclv4_in_cfg(vlan_row, acl_row);
            if (vlan_row->n_aclv4_in_cfg_version) {
                pending_cfg_version = vlan_row->aclv4_in_cfg_version[0] + 1;
            } else {
                pending_cfg_version = 0;
            }
            ovsrec_vlan_set_aclv4_in_cfg_version(vlan_row, &pending_cfg_version, 1);
        } else {
            vty_out(vty, "%% Unsupported ACL type or direction%s", VTY_NEWLINE);
            cli_do_config_abort(transaction);
            return CMD_ERR_NOTHING_TODO;
        }
    }

    /* Complete transaction */
    txn_status = cli_do_config_finish(transaction);
    if (txn_status != TXN_SUCCESS && txn_status != TXN_UNCHANGED) {
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }

    /* Wait until ACL apply either succeeds or fails and report to user */
    return wait_for_acl_apply_status(interface_type, interface_id,
                                     acl_type, direction,
                                     pending_cfg_version);
}

/**
 * Un-apply an ACL from an interface in a specified direction
 *
 * @param  interface_type  Interface (Port/VLAN) type string
 * @param  interface_id    Interface (Port/VLAN) identifier string
 * @param  acl_type        ACL type string
 * @param  acl_name        ACL name string
 * @param  direction       Direction of traffic ACL is applied to
 *
 * @retval CMD_SUCCESS           on success
 * @retval CMD_OVSDB_FAILURE     on database/transaction failure
 * @retval CMD_ERR_NOTHING_TODO  on bad parameter/value
 */
static int
cli_unapply_acl (const char *interface_type,
                 const char *interface_id,
                 const char *acl_type,
                 const char *acl_name,
                 const char *direction)
{
    struct ovsdb_idl_txn *transaction;
    enum ovsdb_idl_txn_status txn_status;
    const struct ovsrec_acl *acl_row;
    int64_t pending_cfg_version;

    /* Start transaction */
    transaction = cli_do_config_start();
    if (!transaction) {
        VLOG_ERR("Unable to acquire transaction");
        return CMD_OVSDB_FAILURE;
    }

    /* Get ACL row */
    acl_row = get_acl_by_type_name(acl_type, acl_name);
    if (!acl_row) {
        vty_out(vty, "%% ACL does not exist%s", VTY_NEWLINE);
        cli_do_config_abort(transaction);
        return CMD_ERR_NOTHING_TODO;
    }

    /* Port (unfortunately called "interface" in the CLI) */
    if (!strcmp(interface_type, "interface")) {
        const struct ovsrec_port *port_row;
        /* Get Port row */
        port_row = get_port_by_name(interface_id);
        if (!port_row) {
            vty_out(vty, "%% Port does not exist%s", VTY_NEWLINE);
            cli_do_config_abort(transaction);
            return CMD_ERR_NOTHING_TODO;
        }

        if (!strcmp(acl_type, "ipv4") && !strcmp(direction, "in")) {
            /* Check that any ACL is currently applied to the port */
            if (!port_row->aclv4_in_applied) {
                vty_out(vty, "%% No ACL is applied to port %s", VTY_NEWLINE);
                cli_do_config_abort(transaction);
                return CMD_ERR_NOTHING_TODO;
            }

            /* Check that the requested ACL to remove is the one applied to port */
            if (strcmp(acl_name, port_row->aclv4_in_applied->name)) {
                vty_out(vty, "%% ACL %s is applied to port %s, not %s%s",
                        port_row->aclv4_in_applied->name,
                        port_row->name, acl_name, VTY_NEWLINE);
                cli_do_config_abort(transaction);
                return CMD_ERR_NOTHING_TODO;
            }

            /* Un-apply the requested ACL application from the Port */
            VLOG_DBG("Removing ACL application port=%s acl_name=%s", interface_id, acl_name);
            ovsrec_port_set_aclv4_in_cfg(port_row, NULL);
            if (port_row->n_aclv4_in_cfg_version) {
                pending_cfg_version = port_row->aclv4_in_cfg_version[0] + 1;
            } else {
                pending_cfg_version = 0;
            }
            ovsrec_port_set_aclv4_in_cfg_version(port_row, &pending_cfg_version, 1);
        } else {
            vty_out(vty, "%% Unsupported ACL type or direction%s", VTY_NEWLINE);
            cli_do_config_abort(transaction);
            return CMD_ERR_NOTHING_TODO;
        }

    } else if (!strcmp(interface_type, "vlan")) {

        const struct ovsrec_vlan *vlan_row;
        /* Get VLAN row */
        vlan_row = get_vlan_by_id_str(interface_id);
        if (!vlan_row) {
            vty_out(vty, "%% VLAN does not exist%s", VTY_NEWLINE);
            cli_do_config_abort(transaction);
            return CMD_ERR_NOTHING_TODO;
        }

        if (!strcmp(acl_type, "ipv4") && !strcmp(direction, "in")) {
            /* Check that any ACL is currently applied to the VLAN */
            if (!vlan_row->aclv4_in_applied) {
                vty_out(vty, "%% No ACL is applied to VLAN %s", VTY_NEWLINE);
                cli_do_config_abort(transaction);
                return CMD_ERR_NOTHING_TODO;
            }

            /* Check that the requested ACL to remove is the one applied to vlan */
            if (strcmp(acl_name, vlan_row->aclv4_in_applied->name)) {
                vty_out(vty, "%% ACL %s is applied to VLAN %" PRId64 ", not %s%s",
                        vlan_row->aclv4_in_applied->name,
                        vlan_row->id, acl_name, VTY_NEWLINE);
                cli_do_config_abort(transaction);
                return CMD_ERR_NOTHING_TODO;
            }

            /* Un-apply the requested ACL application from the VLAN */
            VLOG_DBG("Removing ACL application vlan=%s acl_name=%s", interface_id, acl_name);
            ovsrec_vlan_set_aclv4_in_cfg(vlan_row, NULL);
            if (vlan_row->n_aclv4_in_cfg_version) {
                pending_cfg_version = vlan_row->aclv4_in_cfg_version[0] + 1;
            } else {
                pending_cfg_version = 0;
            }
            ovsrec_vlan_set_aclv4_in_cfg_version(vlan_row, &pending_cfg_version, 1);
        } else {
            vty_out(vty, "%% Unsupported ACL type or direction%s", VTY_NEWLINE);
            cli_do_config_abort(transaction);
            return CMD_ERR_NOTHING_TODO;
        }
    }

    /* Complete transaction */
    txn_status = cli_do_config_finish(transaction);
    if (txn_status != TXN_SUCCESS && txn_status != TXN_UNCHANGED) {
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }

    /* Wait until ACL un-apply either succeeds or fails and report to user */
    return wait_for_acl_apply_status(interface_type, interface_id,
                                     acl_type, direction,
                                     pending_cfg_version);
}

/**
 * Print inbound IPv4 statistics for any ACLs applied to a given Port
 *
 * @param port_row Pointer to Port row
 */
static inline void
print_port_aclv4_in_statistics(const struct ovsrec_port *port_row)
{
    int64_t hit_count;
    char *ace_str;
    int i;

    vty_out(vty, "Interface %s (in):%s", port_row->name, VTY_NEWLINE);
    vty_out(vty, "%20s  %s%s", "Hit Count", "Configuration", VTY_NEWLINE);

    /* Print each ACL entry as a single line (ala CLI input) */
    for (i = 0; i < port_row->aclv4_in_applied->n_cur_aces; i ++) {
        /* If entry has or is a comment, print as its own line */
        if (port_row->aclv4_in_applied->value_cur_aces[i]->comment) {
            vty_out(vty,
                    "%20s  %" PRId64 " comment %s%s",
                    "",
                    port_row->aclv4_in_applied->key_cur_aces[i],
                    port_row->aclv4_in_applied->value_cur_aces[i]->comment,
                    VTY_NEWLINE);
        }
        if (port_row->aclv4_in_applied->value_cur_aces[i]->action) {
            if (port_row->aclv4_in_applied->value_cur_aces[i]->n_count) {
                hit_count = ovsrec_port_aclv4_in_statistics_getvalue(
                                    port_row, port_row->aclv4_in_applied->key_cur_aces[i]);
                vty_out(vty, "%20" PRId64, hit_count);
            } else {
                vty_out(vty, "%20s", "-");
            }
            ace_str = acl_entry_config_to_string(port_row->aclv4_in_applied->key_cur_aces[i],
                                                 port_row->aclv4_in_applied->value_cur_aces[i]);
            vty_out(vty, "  %s%s", ace_str, VTY_NEWLINE);
            free(ace_str);
        }
    }
}

/**
 * Print inbound IPv4 statistics for any ACLs applied to a given VLAN
 *
 * @param vlan_row Pointer to VLAN row
 */
static inline void
print_vlan_aclv4_in_statistics(const struct ovsrec_vlan *vlan_row)
{
    int64_t hit_count;
    char *ace_str;
    int i;

    vty_out(vty,"VLAN %" PRId64 " (in):%s", vlan_row->id, VTY_NEWLINE);
    vty_out(vty, "%20s  %s%s", "Hit Count", "Configuration", VTY_NEWLINE);

    /* Print each ACL entry as a single line (ala CLI input) */
    for (i = 0; i < vlan_row->aclv4_in_applied->n_cur_aces; i ++) {
        /* If entry has or is a comment, print as its own line */
        if (vlan_row->aclv4_in_applied->value_cur_aces[i]->comment) {
            vty_out(vty,
                    "%20s  %" PRId64 " comment %s%s",
                    "",
                    vlan_row->aclv4_in_applied->key_cur_aces[i],
                    vlan_row->aclv4_in_applied->value_cur_aces[i]->comment,
                    VTY_NEWLINE);
        }
        if (vlan_row->aclv4_in_applied->value_cur_aces[i]->action) {
            if (vlan_row->aclv4_in_applied->value_cur_aces[i]->n_count) {
                hit_count = ovsrec_vlan_aclv4_in_statistics_getvalue(
                                    vlan_row, vlan_row->aclv4_in_applied->key_cur_aces[i]);
                vty_out(vty, "%20" PRId64, hit_count);
            } else {
                vty_out(vty, "%20s", "-");
            }
            ace_str = acl_entry_config_to_string(vlan_row->aclv4_in_applied->key_cur_aces[i],
                                                 vlan_row->aclv4_in_applied->value_cur_aces[i]);
            vty_out(vty, "  %s%s", ace_str, VTY_NEWLINE);
            free(ace_str);
        }
    }
}

/**
 * Print statistics for a specified ACL (optionally for a specified interface
 * and/or direction)
 *
 * @param  acl_type        ACL type string
 * @param  acl_name        ACL name string
 * @param  interface_type  Interface (Port/VLAN) type string
 * @param  interface_id    Interface (Port/VLAN) identifier string
 * @param  direction       Direction of traffic ACL is applied to
 *
 * @retval CMD_SUCCESS           on success
 * @retval CMD_OVSDB_FAILURE     on database/transaction failure
 * @retval CMD_ERR_NOTHING_TODO  on bad parameter/value
 */
static int
cli_print_acl_statistics (const char *acl_type,
                          const char *acl_name,
                          const char *interface_type,
                          const char *interface_id,
                          const char *direction)
{
    const struct ovsrec_port *port_row;
    const struct ovsrec_vlan *vlan_row;
    const struct ovsrec_acl *acl_row;

    VLOG_DBG("Showing statistics for %s ACL %s %s=%s direction=%s",
            acl_type, acl_name, interface_type, interface_id, direction);

    acl_row = get_acl_by_type_name(acl_type, acl_name);
    if (!acl_row) {
        vty_out(vty, "%% ACL %s does not exist%s", acl_name, VTY_NEWLINE);
        return CMD_ERR_NOTHING_TODO;
    }

    /* No interface specified (implicit "all" interface type/id/direction) */
    if (!interface_type) {
        vty_out(vty, "Statistics for ACL %s (%s):%s", acl_row->name, acl_row->list_type, VTY_NEWLINE);
        OVSREC_PORT_FOR_EACH(port_row, idl) {
            if (port_row->aclv4_in_applied && (port_row->aclv4_in_applied == acl_row)) {
                print_port_aclv4_in_statistics(port_row);
            }
        }
        OVSREC_VLAN_FOR_EACH(vlan_row, idl) {
            if (vlan_row->aclv4_in_applied && (vlan_row->aclv4_in_applied == acl_row)) {
                print_vlan_aclv4_in_statistics(vlan_row);
            }
        }
    /* Port (unfortunately called "interface" in the CLI) */
    } else if (interface_type && !strcmp(interface_type, "interface")) {
        /* Get Port row */
        port_row = get_port_by_name(interface_id);
        if (!port_row) {
            vty_out(vty, "%% Port %s does not exist%s", interface_id, VTY_NEWLINE);
            return CMD_ERR_NOTHING_TODO;
        }
        if (port_row->aclv4_in_applied && (port_row->aclv4_in_applied == acl_row)) {
            vty_out(vty, "Statistics for ACL %s (%s):%s", acl_row->name, acl_row->list_type, VTY_NEWLINE);
            print_port_aclv4_in_statistics(port_row);
        } else {
            vty_out(vty, "%% Specified ACL not applied to interface%s", VTY_NEWLINE);
            return CMD_ERR_NOTHING_TODO;
        }
    /* VLAN */
    } else if (interface_type && !strcmp(interface_type, "vlan")) {
        /* Get VLAN row */
        vlan_row = get_vlan_by_id_str(interface_id);
        if (!vlan_row) {
            vty_out(vty, "%% VLAN %s does not exist%s", interface_id, VTY_NEWLINE);
            return CMD_ERR_NOTHING_TODO;
        }
        if (vlan_row->aclv4_in_applied && (vlan_row->aclv4_in_applied == acl_row)) {
            vty_out(vty, "Statistics for ACL %s (%s):%s", acl_row->name, acl_row->list_type, VTY_NEWLINE);
            print_vlan_aclv4_in_statistics(vlan_row);
        } else {
            vty_out(vty, "%% Specified ACL not applied to VLAN%s", VTY_NEWLINE);
            return CMD_ERR_NOTHING_TODO;
        }
    }
    return CMD_SUCCESS;
}

/**
 * Clear ACL statistics (optionally for a specific ACL, interface, direction)
 *
 * @param  acl_type        ACL type string
 * @param  acl_name        ACL name string
 * @param  interface_type  Interface (Port/VLAN) type string
 * @param  interface_id    Interface (Port/VLAN) identifier string
 * @param  direction       Direction of traffic ACL is applied to
 *
 * @retval CMD_SUCCESS           on success
 * @retval CMD_OVSDB_FAILURE     on database/transaction failure
 * @retval CMD_ERR_NOTHING_TODO  on bad parameter/value
 */
static int
cli_clear_acl_statistics (const char *acl_type,
                          const char *acl_name,
                          const char *interface_type,
                          const char *interface_id,
                          const char *direction)
{
    struct ovsdb_idl_txn *transaction;
    enum ovsdb_idl_txn_status txn_status;
    const struct ovsrec_port *port_row;
    const struct ovsrec_vlan *vlan_row;
    const struct ovsrec_acl *acl_row;

    VLOG_DBG("Clearing statistics for %s ACL %s %s=%s direction=%s",
            acl_type, acl_name, interface_type, interface_id, direction);

    /* Start transaction */
    transaction = cli_do_config_start();
    if (!transaction) {
        VLOG_ERR("Unable to acquire transaction");
        return CMD_OVSDB_FAILURE;
    }

    /* No ACL specified (implicit "all" applied ACLs) */
    if (!acl_name) {
        OVSREC_PORT_FOR_EACH(port_row, idl) {
            VLOG_DBG("Clearing ACL statistics port=%s", port_row->name);
            ovsrec_port_set_aclv4_in_statistics(port_row, NULL, NULL, 0);
        }
        OVSREC_VLAN_FOR_EACH(vlan_row, idl) {
            VLOG_DBG("Clearing ACL statistics vlan=%" PRId64 "", vlan_row->id);
            ovsrec_vlan_set_aclv4_in_statistics(vlan_row, NULL, NULL, 0);
        }
    /* ACL specified */
    } else {
        acl_row = get_acl_by_type_name(acl_type, acl_name);
        if (!acl_row) {
            vty_out(vty, "%% ACL %s does not exist%s", acl_name, VTY_NEWLINE);
            return CMD_ERR_NOTHING_TODO;
        }
        /* No interface specified (implicit "all" interface type/id/direction) */
        if (!interface_type) {
            OVSREC_PORT_FOR_EACH(port_row, idl) {
                if (port_row->aclv4_in_applied && (port_row->aclv4_in_applied == acl_row)) {
                    VLOG_DBG("Clearing ACL statistics port=%s acl_name=%s", port_row->name, acl_name);
                    ovsrec_port_set_aclv4_in_statistics(port_row, NULL, NULL, 0);
                }
            }
            OVSREC_VLAN_FOR_EACH(vlan_row, idl) {
                if (vlan_row->aclv4_in_applied && (vlan_row->aclv4_in_applied == acl_row)) {
                    VLOG_DBG("Clearing ACL statistics vlan=%" PRId64 " acl_name=%s", vlan_row->id, acl_name);
                    ovsrec_vlan_set_aclv4_in_statistics(vlan_row, NULL, NULL, 0);
                }
            }
        /* Port (unfortunately called "interface" in the CLI) */
        } else if (!strcmp(interface_type, "interface")) {
            /* Get Port row */
            port_row = get_port_by_name(interface_id);
            if (!port_row) {
                vty_out(vty, "%% Port %s does not exist%s", interface_id, VTY_NEWLINE);
                return CMD_ERR_NOTHING_TODO;
            }
            if (port_row->aclv4_in_applied && (port_row->aclv4_in_applied == acl_row)) {
                VLOG_DBG("Clearing ACL statistics port=%s acl_name=%s", port_row->name, acl_name);
                ovsrec_port_set_aclv4_in_statistics(port_row, NULL, NULL, 0);
            } else {
                vty_out(vty, "%% Specified ACL not applied to interface%s", VTY_NEWLINE);
                return CMD_ERR_NOTHING_TODO;
            }
        /* VLAN */
        } else if (!strcmp(interface_type, "vlan")) {
            /* Get VLAN row */
            vlan_row = get_vlan_by_id_str(interface_id);
            if (!vlan_row) {
                vty_out(vty, "%% VLAN %s does not exist%s", interface_id, VTY_NEWLINE);
                return CMD_ERR_NOTHING_TODO;
            }
            if (vlan_row->aclv4_in_applied && (vlan_row->aclv4_in_applied == acl_row)) {
                VLOG_DBG("Clearing ACL statistics vlan=%" PRId64 " acl_name=%s", vlan_row->id, acl_name);
                ovsrec_vlan_set_aclv4_in_statistics(vlan_row, NULL, NULL, 0);
            } else {
                vty_out(vty, "%% Specified ACL not applied to VLAN%s", VTY_NEWLINE);
                return CMD_ERR_NOTHING_TODO;
            }
        }
    }

    /* Complete transaction */
    txn_status = cli_do_config_finish(transaction);
    if (txn_status == TXN_SUCCESS || txn_status == TXN_UNCHANGED) {
        return CMD_SUCCESS;
    } else {
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }
}

/**
 * Set the ACL logging timer to a specified value (in seconds)
 *
 * @param  timer_value ACL log timer frequency (in seconds)
 *
 * @retval CMD_SUCCESS           on success
 * @retval CMD_OVSDB_FAILURE     on database/transaction failure
 */
static int
cli_set_acl_log_timer(const char* timer_value)
{
    struct ovsdb_idl_txn *transaction;
    enum ovsdb_idl_txn_status txn_status;
    const struct ovsrec_system *ovs;
    struct smap other_config;

    VLOG_DBG("Setting ACL log timer to %s", timer_value);

    /* Start transaction */
    transaction = cli_do_config_start();
    if (!transaction) {
        VLOG_ERR("Unable to acquire transaction");
        return CMD_OVSDB_FAILURE;
    }

    /* Get System table */
    ovs = ovsrec_system_first(idl);
    if (!ovs) {
        cli_do_config_abort(transaction);
        assert(0);
        return CMD_OVSDB_FAILURE;
    }

    /* Copy current "other_config" column from System table */
    smap_clone(&other_config, &ovs->other_config);

    /* Remove any existing value (smap_add doesn't replace) */
    smap_remove(&other_config, ACL_LOG_TIMER_STR);

    /* Only set "other_config" record for non-default value */
    if (strcmp(timer_value, ACL_LOG_TIMER_DEFAULT_STR))
    {
        smap_add(&other_config, ACL_LOG_TIMER_STR, timer_value);
    }

    /* Set new "other_config" column in System table */
    ovsrec_system_set_other_config(ovs, &other_config);

    /* Complete transaction */
    txn_status = cli_do_config_finish(transaction);
    if (txn_status == TXN_SUCCESS || txn_status == TXN_UNCHANGED) {
        return CMD_SUCCESS;
    } else {
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }
}

/* = Command Definitions = */

/**
 * Action routine for creating/updating an ACL (entering context)
 */
DEFUN (cli_access_list,
       cli_access_list_cmd,
       "access-list ip NAME",
       ACL_STR
       ACL_IP_STR
       ACL_NAME_STR
      )
{
    /* static buffers because CLI context persists past this function */
    static char acl_ip_version[IP_VER_STR_LEN];
    static char acl_name[MAX_ACL_NAME_LENGTH];

    if ((strnlen(argv[0], MAX_ACL_NAME_LENGTH) < MAX_ACL_NAME_LENGTH)) {
        strncpy(acl_ip_version, "ipv4", IP_VER_STR_LEN);
        strncpy(acl_name, argv[0], MAX_ACL_NAME_LENGTH);
    } else {
        return CMD_ERR_NO_MATCH;
    }

    /* Same name can be used with different IP versions; consider name sub-index */
    vty->index = acl_ip_version;
    vty->index_sub = acl_name;
    vty->node = ACCESS_LIST_NODE;

    return cli_create_acl_if_needed(CONST_CAST(char*,vty->index),      /* Type */
                                    CONST_CAST(char*,vty->index_sub)); /* Name */
}

/**
 * Action routine for deleting an ACL
 */
DEFUN (cli_no_access_list,
       cli_no_access_list_cmd,
       "no access-list ip NAME",
       NO_STR
       ACL_STR
       ACL_IP_STR
       ACL_NAME_STR
      )
{
    return cli_delete_acl("ipv4",
                          CONST_CAST(char*,argv[0]));
}

/**
 * Action routine for showing all ACLs
 */
DEFUN (cli_show_access_list,
       cli_show_access_list_cmd,
       "show access-list { config }",
       SHOW_STR
       ACL_STR
       ACL_CFG_STR
      )
{
    return cli_print_acls(NULL,                       /* Type */
                          NULL,                       /* Name */
                          CONST_CAST(char*,argv[0])); /* Config */
}

/**
 * Action routine for showing all ACLs of a specified type
 */
DEFUN (cli_show_access_list_type,
       cli_show_access_list_type_cmd,
       "show access-list ip { config }",
       SHOW_STR
       ACL_STR
       ACL_IP_STR
       ACL_CFG_STR
      )
{
    return cli_print_acls("ipv4",                     /* Type */
                          NULL,                       /* Name */
                          CONST_CAST(char*,argv[0])); /* Config */
}

/**
 * Action routine for showing a single ACL (specified name + type)
 */
DEFUN (cli_show_access_list_type_name,
       cli_show_access_list_type_name_cmd,
       "show access-list ip NAME { config }",
       SHOW_STR
       ACL_STR
       ACL_IP_STR
       ACL_NAME_STR
       ACL_CFG_STR
      )
{
    return cli_print_acls("ipv4",                     /* Type */
                          CONST_CAST(char*,argv[0]),  /* Name */
                          CONST_CAST(char*,argv[1])); /* Config */
}

/**
 * Action routine for resequencing an ACL
 */
DEFUN (cli_access_list_resequence,
       cli_access_list_resequence_cmd,
       "access-list ip NAME resequence " ACE_SEQ_CMDSTR " " ACE_SEQ_CMDSTR,
       ACL_STR
       ACL_IP_STR
       ACL_NAME_STR
       "Re-number entries\n"
       "Starting sequence number\n"
       "Re-sequence increment\n"
      )
{
    return cli_resequence_acl("ipv4",
                              CONST_CAST(char*,argv[0]),
                              CONST_CAST(char*,argv[1]),
                              CONST_CAST(char*,argv[2]));
}

/* ACE create/update command functions.
 * These are PAINFUL to express due to vtysh's lack of handling for optional
 * tokens or sequences in the middle of a command. The relevant combinations
 * are below and result in 18 combinations (and therefore "DEFUN" calls)
 *
 * - With or without sequence number
 * - Layer 4 source port options (3)
 *   - None
 *   - Operation and port specified
 *   - Range and min+max ports specified
 * - Layer 4 destination port options (3)
 *   - None
 *   - Operation and port specified
 *   - Range and min+max ports specified
 *
 * Adding another optional parameter mid-command will double this number again.
 */

/**
 * Action routine for setting an ACE
 */
DEFUN (cli_access_list_entry,
       cli_access_list_entry_cmd,
       /* start of cmdstr, broken up to help readability */
       ACE_SEQ_CMDSTR
       ACE_ACTION_CMDSTR
       ACE_ALL_PROTOCOLS_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_ADDITIONAL_OPTIONS_CMDSTR
       , /* end of cmdstr, comment to avoid accidental comma loss */

       /* helpstr, newline delimited */
       ACE_SEQ_HELPSTR
       ACE_ACTION_HELPSTR
       ACE_ALL_PROTOCOLS_HELPSTR
       ACE_SRC_IP_ADDRESS_HELPSTR
       ACE_DST_IP_ADDRESS_HELPSTR
       ACE_ADDITIONAL_OPTIONS_HELPSTR
      )
{
    return cli_create_update_ace(CONST_CAST(char*,vty->index),     /* Type */
                                 CONST_CAST(char*,vty->index_sub), /* Name */
                                 CONST_CAST(char*,argv[0]),        /* Sequence number */
                                 CONST_CAST(char*,argv[1]),        /* Action */
                                 CONST_CAST(char*,argv[2]),        /* IP Protocol */
                                 CONST_CAST(char*,argv[3]),        /* Source IP */
                                 NULL,                             /* Source Port Operator */
                                 NULL,                             /* Source Port 1 */
                                 NULL,                             /* Source Port 2 */
                                 CONST_CAST(char*,argv[4]),        /* Destination IP */
                                 NULL,                             /* Destination Port Operator */
                                 NULL,                             /* Destination Port 1 */
                                 NULL,                             /* Destination Port 2 */
                                 CONST_CAST(char*,argv[5]),        /* Log */
                                 CONST_CAST(char*,argv[6]),        /* Count */
                                 NULL);                            /* Comment */
}

/**
 * Action routine for setting an ACE with a source port operator specified
 */
DEFUN (cli_access_list_entry_src_port_op,
       cli_access_list_entry_src_port_op_cmd,
       /* start of cmdstr, broken up to help readability */
       ACE_SEQ_CMDSTR
       ACE_ACTION_CMDSTR
       ACE_PORT_PROTOCOLS_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_PORT_OPER_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_ADDITIONAL_OPTIONS_CMDSTR
       , /* end of cmdstr, comment to avoid accidental comma loss */

       /* helpstr, newline delimited */
       ACE_SEQ_HELPSTR
       ACE_ACTION_HELPSTR
       ACE_PORT_PROTOCOLS_HELPSTR
       ACE_SRC_IP_ADDRESS_HELPSTR
       ACE_SRC_PORT_OPER_HELPSTR
       ACE_DST_IP_ADDRESS_HELPSTR
       ACE_ADDITIONAL_OPTIONS_HELPSTR
      )
{
    return cli_create_update_ace(CONST_CAST(char*,vty->index),     /* Type */
                                 CONST_CAST(char*,vty->index_sub), /* Name */
                                 CONST_CAST(char*,argv[0]),        /* Sequence number */
                                 CONST_CAST(char*,argv[1]),        /* Action */
                                 CONST_CAST(char*,argv[2]),        /* IP Protocol */
                                 CONST_CAST(char*,argv[3]),        /* Source IP */
                                 CONST_CAST(char*,argv[4]),        /* Source Port Operator */
                                 CONST_CAST(char*,argv[5]),        /* Source Port 1 */
                                 NULL,                             /* Source Port 2 */
                                 CONST_CAST(char*,argv[6]),        /* Destination IP */
                                 NULL,                             /* Destination Port Operator */
                                 NULL,                             /* Destination Port 1 */
                                 NULL,                             /* Destination Port 2 */
                                 CONST_CAST(char*,argv[7]),        /* Log */
                                 CONST_CAST(char*,argv[8]),        /* Count */
                                 NULL);                            /* Comment */
}

/**
 * Action routine for setting an ACE with a source port range specified
 */
DEFUN (cli_access_list_entry_src_port_range,
       cli_access_list_entry_src_port_range_cmd,
       /* start of cmdstr, broken up to help readability */
       ACE_SEQ_CMDSTR
       ACE_ACTION_CMDSTR
       ACE_PORT_PROTOCOLS_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_PORT_RANGE_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_ADDITIONAL_OPTIONS_CMDSTR
       , /* end of cmdstr, comment to avoid accidental comma loss */

       /* helpstr, newline delimited */
       ACE_SEQ_HELPSTR
       ACE_ACTION_HELPSTR
       ACE_PORT_PROTOCOLS_HELPSTR
       ACE_SRC_IP_ADDRESS_HELPSTR
       ACE_SRC_PORT_RANGE_HELPSTR
       ACE_DST_IP_ADDRESS_HELPSTR
       ACE_ADDITIONAL_OPTIONS_HELPSTR
      )
{
    return cli_create_update_ace(CONST_CAST(char*,vty->index),     /* Type */
                                 CONST_CAST(char*,vty->index_sub), /* Name */
                                 CONST_CAST(char*,argv[0]),        /* Sequence number */
                                 CONST_CAST(char*,argv[1]),        /* Action */
                                 CONST_CAST(char*,argv[2]),        /* IP Protocol */
                                 CONST_CAST(char*,argv[3]),        /* Source IP */
                                 CONST_CAST(char*,argv[4]),        /* Source Port Operator */
                                 CONST_CAST(char*,argv[5]),        /* Source Port 1 */
                                 CONST_CAST(char*,argv[6]),        /* Source Port 2 */
                                 CONST_CAST(char*,argv[7]),        /* Destination IP */
                                 NULL,                             /* Destination Port Operator */
                                 NULL,                             /* Destination Port 1 */
                                 NULL,                             /* Destination Port 2 */
                                 CONST_CAST(char*,argv[8]),        /* Log */
                                 CONST_CAST(char*,argv[9]),        /* Count */
                                 NULL);                            /* Comment */
}

/**
 * Action routine for setting an ACE with a destination port operator specified
 */
DEFUN (cli_access_list_entry_dst_port_op,
       cli_access_list_entry_dst_port_op_cmd,
       /* start of cmdstr, broken up to help readability */
       ACE_SEQ_CMDSTR
       ACE_ACTION_CMDSTR
       ACE_PORT_PROTOCOLS_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_PORT_OPER_CMDSTR
       ACE_ADDITIONAL_OPTIONS_CMDSTR
       , /* end of cmdstr, comment to avoid accidental comma loss */

       /* helpstr, newline delimited */
       ACE_SEQ_HELPSTR
       ACE_ACTION_HELPSTR
       ACE_PORT_PROTOCOLS_HELPSTR
       ACE_SRC_IP_ADDRESS_HELPSTR
       ACE_DST_IP_ADDRESS_HELPSTR
       ACE_DST_PORT_OPER_HELPSTR
       ACE_ADDITIONAL_OPTIONS_HELPSTR
      )
{
    return cli_create_update_ace(CONST_CAST(char*,vty->index),     /* Type */
                                 CONST_CAST(char*,vty->index_sub), /* Name */
                                 CONST_CAST(char*,argv[0]),        /* Sequence number */
                                 CONST_CAST(char*,argv[1]),        /* Action */
                                 CONST_CAST(char*,argv[2]),        /* IP Protocol */
                                 CONST_CAST(char*,argv[3]),        /* Source IP */
                                 NULL,                             /* Source Port Operator */
                                 NULL,                             /* Source Port 1 */
                                 NULL,                             /* Source Port 2 */
                                 CONST_CAST(char*,argv[4]),        /* Destination IP */
                                 CONST_CAST(char*,argv[5]),        /* Destination Port Operator */
                                 CONST_CAST(char*,argv[6]),        /* Destination Port 1 */
                                 NULL,                             /* Destination Port 2 */
                                 CONST_CAST(char*,argv[7]),        /* Log */
                                 CONST_CAST(char*,argv[8]),        /* Count */
                                 NULL);                            /* Comment */
}

/**
 * Action routine for setting an ACE with a destination port range specified
 */
DEFUN (cli_access_list_entry_dst_port_range,
       cli_access_list_entry_dst_port_range_cmd,
       /* start of cmdstr, broken up to help readability */
       ACE_SEQ_CMDSTR
       ACE_ACTION_CMDSTR
       ACE_PORT_PROTOCOLS_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_PORT_RANGE_CMDSTR
       ACE_ADDITIONAL_OPTIONS_CMDSTR
       , /* end of cmdstr, comment to avoid accidental comma loss */

       /* helpstr, newline delimited */
       ACE_SEQ_HELPSTR
       ACE_ACTION_HELPSTR
       ACE_PORT_PROTOCOLS_HELPSTR
       ACE_SRC_IP_ADDRESS_HELPSTR
       ACE_DST_IP_ADDRESS_HELPSTR
       ACE_DST_PORT_RANGE_HELPSTR
       ACE_ADDITIONAL_OPTIONS_HELPSTR
      )
{
    return cli_create_update_ace(CONST_CAST(char*,vty->index),     /* Type */
                                 CONST_CAST(char*,vty->index_sub), /* Name */
                                 CONST_CAST(char*,argv[0]),        /* Sequence number */
                                 CONST_CAST(char*,argv[1]),        /* Action */
                                 CONST_CAST(char*,argv[2]),        /* IP Protocol */
                                 CONST_CAST(char*,argv[3]),        /* Source IP */
                                 NULL,                             /* Source Port Operator */
                                 NULL,                             /* Source Port 1 */
                                 NULL,                             /* Source Port 2 */
                                 CONST_CAST(char*,argv[4]),        /* Destination IP */
                                 CONST_CAST(char*,argv[5]),        /* Destination Port Operator */
                                 CONST_CAST(char*,argv[6]),        /* Destination Port 1 */
                                 CONST_CAST(char*,argv[7]),        /* Destination Port 2 */
                                 CONST_CAST(char*,argv[8]),        /* Log */
                                 CONST_CAST(char*,argv[9]),        /* Count */
                                 NULL);                            /* Comment */
}

/**
 * Action routine for setting an ACE with both source and destination port
 * operators specified
 */
DEFUN (cli_access_list_entry_src_port_op_dst_port_op,
       cli_access_list_entry_src_port_op_dst_port_op_cmd,
       /* start of cmdstr, broken up to help readability */
       ACE_SEQ_CMDSTR
       ACE_ACTION_CMDSTR
       ACE_PORT_PROTOCOLS_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_PORT_OPER_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_PORT_OPER_CMDSTR
       ACE_ADDITIONAL_OPTIONS_CMDSTR
       , /* end of cmdstr, comment to avoid accidental comma loss */

       /* helpstr, newline delimited */
       ACE_SEQ_HELPSTR
       ACE_ACTION_HELPSTR
       ACE_PORT_PROTOCOLS_HELPSTR
       ACE_SRC_IP_ADDRESS_HELPSTR
       ACE_SRC_PORT_OPER_HELPSTR
       ACE_DST_IP_ADDRESS_HELPSTR
       ACE_DST_PORT_OPER_HELPSTR
       ACE_ADDITIONAL_OPTIONS_HELPSTR
      )
{
    return cli_create_update_ace(CONST_CAST(char*,vty->index),     /* Type */
                                 CONST_CAST(char*,vty->index_sub), /* Name */
                                 CONST_CAST(char*,argv[0]),        /* Sequence number */
                                 CONST_CAST(char*,argv[1]),        /* Action */
                                 CONST_CAST(char*,argv[2]),        /* IP Protocol */
                                 CONST_CAST(char*,argv[3]),        /* Source IP */
                                 CONST_CAST(char*,argv[4]),        /* Source Port Operator */
                                 CONST_CAST(char*,argv[5]),        /* Source Port 1 */
                                 NULL,                             /* Source Port 2 */
                                 CONST_CAST(char*,argv[6]),        /* Destination IP */
                                 CONST_CAST(char*,argv[7]),        /* Destination Port Operator */
                                 CONST_CAST(char*,argv[8]),        /* Destination Port 1 */
                                 NULL,                             /* Destination Port 2 */
                                 CONST_CAST(char*,argv[9]),        /* Log */
                                 CONST_CAST(char*,argv[10]),       /* Count */
                                 NULL);                            /* Comment */
}

/**
 * Action routine for setting an ACE with both source and destination port
 * ranges specified
 */
DEFUN (cli_access_list_entry_src_port_range_dst_port_range,
       cli_access_list_entry_src_port_range_dst_port_range_cmd,
       /* start of cmdstr, broken up to help readability */
       ACE_SEQ_CMDSTR
       ACE_ACTION_CMDSTR
       ACE_PORT_PROTOCOLS_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_PORT_RANGE_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_PORT_RANGE_CMDSTR
       ACE_ADDITIONAL_OPTIONS_CMDSTR
       , /* end of cmdstr, comment to avoid accidental comma loss */

       /* helpstr, newline delimited */
       ACE_SEQ_HELPSTR
       ACE_ACTION_HELPSTR
       ACE_PORT_PROTOCOLS_HELPSTR
       ACE_SRC_IP_ADDRESS_HELPSTR
       ACE_SRC_PORT_RANGE_HELPSTR
       ACE_DST_IP_ADDRESS_HELPSTR
       ACE_DST_PORT_RANGE_HELPSTR
       ACE_ADDITIONAL_OPTIONS_HELPSTR
      )
{
    return cli_create_update_ace(CONST_CAST(char*,vty->index),     /* Type */
                                 CONST_CAST(char*,vty->index_sub), /* Name */
                                 CONST_CAST(char*,argv[0]),        /* Sequence number */
                                 CONST_CAST(char*,argv[1]),        /* Action */
                                 CONST_CAST(char*,argv[2]),        /* IP Protocol */
                                 CONST_CAST(char*,argv[3]),        /* Source IP */
                                 CONST_CAST(char*,argv[4]),        /* Source Port Operator */
                                 CONST_CAST(char*,argv[5]),        /* Source Port 1 */
                                 CONST_CAST(char*,argv[6]),        /* Source Port 2 */
                                 CONST_CAST(char*,argv[7]),        /* Destination IP */
                                 CONST_CAST(char*,argv[8]),        /* Destination Port Operator */
                                 CONST_CAST(char*,argv[9]),        /* Destination Port 1 */
                                 CONST_CAST(char*,argv[10]),       /* Destination Port 2 */
                                 CONST_CAST(char*,argv[11]),       /* Log */
                                 CONST_CAST(char*,argv[12]),       /* Count */
                                 NULL);                            /* Comment */
}

/**
 * Action routine for setting an ACE with source port operator and destination
 * port range specified
 */
DEFUN (cli_access_list_entry_src_port_op_dst_port_range,
       cli_access_list_entry_src_port_op_dst_port_range_cmd,
       /* start of cmdstr, broken up to help readability */
       ACE_SEQ_CMDSTR
       ACE_ACTION_CMDSTR
       ACE_PORT_PROTOCOLS_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_PORT_OPER_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_PORT_RANGE_CMDSTR
       ACE_ADDITIONAL_OPTIONS_CMDSTR
       , /* end of cmdstr, comment to avoid accidental comma loss */

       /* helpstr, newline delimited */
       ACE_SEQ_HELPSTR
       ACE_ACTION_HELPSTR
       ACE_PORT_PROTOCOLS_HELPSTR
       ACE_SRC_IP_ADDRESS_HELPSTR
       ACE_SRC_PORT_OPER_HELPSTR
       ACE_DST_IP_ADDRESS_HELPSTR
       ACE_DST_PORT_RANGE_HELPSTR
       ACE_ADDITIONAL_OPTIONS_HELPSTR
      )
{
    return cli_create_update_ace(CONST_CAST(char*,vty->index),     /* Type */
                                 CONST_CAST(char*,vty->index_sub), /* Name */
                                 CONST_CAST(char*,argv[0]),        /* Sequence number */
                                 CONST_CAST(char*,argv[1]),        /* Action */
                                 CONST_CAST(char*,argv[2]),        /* IP Protocol */
                                 CONST_CAST(char*,argv[3]),        /* Source IP */
                                 CONST_CAST(char*,argv[4]),        /* Source Port Operator */
                                 CONST_CAST(char*,argv[5]),        /* Source Port 1 */
                                 NULL,                             /* Source Port 2 */
                                 CONST_CAST(char*,argv[6]),        /* Destination IP */
                                 CONST_CAST(char*,argv[7]),        /* Destination Port Operator */
                                 CONST_CAST(char*,argv[8]),        /* Destination Port 1 */
                                 CONST_CAST(char*,argv[9]),        /* Destination Port 2 */
                                 CONST_CAST(char*,argv[10]),       /* Log */
                                 CONST_CAST(char*,argv[11]),       /* Count */
                                 NULL);                            /* Comment */
}

/**
 * Action routine for setting an ACE with source port range and destination
 * port operator specified
 */
DEFUN (cli_access_list_entry_src_port_range_dst_port_op,
       cli_access_list_entry_src_port_range_dst_port_op_cmd,
       /* start of cmdstr, broken up to help readability */
       ACE_SEQ_CMDSTR
       ACE_ACTION_CMDSTR
       ACE_PORT_PROTOCOLS_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_PORT_RANGE_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_PORT_OPER_CMDSTR
       ACE_ADDITIONAL_OPTIONS_CMDSTR
       , /* end of cmdstr, comment to avoid accidental comma loss */

       /* helpstr, newline delimited */
       ACE_SEQ_HELPSTR
       ACE_ACTION_HELPSTR
       ACE_PORT_PROTOCOLS_HELPSTR
       ACE_SRC_IP_ADDRESS_HELPSTR
       ACE_SRC_PORT_RANGE_HELPSTR
       ACE_DST_IP_ADDRESS_HELPSTR
       ACE_DST_PORT_OPER_HELPSTR
       ACE_ADDITIONAL_OPTIONS_HELPSTR
      )
{
    return cli_create_update_ace(CONST_CAST(char*,vty->index),     /* Type */
                                 CONST_CAST(char*,vty->index_sub), /* Name */
                                 CONST_CAST(char*,argv[0]),        /* Sequence number */
                                 CONST_CAST(char*,argv[1]),        /* Action */
                                 CONST_CAST(char*,argv[2]),        /* IP Protocol */
                                 CONST_CAST(char*,argv[3]),        /* Source IP */
                                 CONST_CAST(char*,argv[4]),        /* Source Port Operator */
                                 CONST_CAST(char*,argv[5]),        /* Source Port 1 */
                                 CONST_CAST(char*,argv[6]),        /* Source Port 2 */
                                 CONST_CAST(char*,argv[7]),        /* Destination IP */
                                 CONST_CAST(char*,argv[8]),        /* Destination Port Operator */
                                 CONST_CAST(char*,argv[9]),        /* Destination Port 1 */
                                 NULL,                             /* Destination Port 2 */
                                 CONST_CAST(char*,argv[10]),       /* Log */
                                 CONST_CAST(char*,argv[11]),       /* Count */
                                 NULL);                            /* Comment */
}

/* ACE commands omitting sequence number */

/**
 * Action routine for setting an ACE without a sequence number
 */
DEFUN (cli_access_list_entry_no_seq,
       cli_access_list_entry_no_seq_cmd,
       /* start of cmdstr, broken up to help readability */
       ACE_ACTION_CMDSTR
       ACE_ALL_PROTOCOLS_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_ADDITIONAL_OPTIONS_CMDSTR
       , /* end of cmdstr, comment to avoid accidental comma loss */

       /* helpstr, newline delimited */
       ACE_ACTION_HELPSTR
       ACE_ALL_PROTOCOLS_HELPSTR
       ACE_SRC_IP_ADDRESS_HELPSTR
       ACE_DST_IP_ADDRESS_HELPSTR
       ACE_ADDITIONAL_OPTIONS_HELPSTR
      )
{
    return cli_create_update_ace(CONST_CAST(char*,vty->index),     /* Type */
                                 CONST_CAST(char*,vty->index_sub), /* Name */
                                 NULL,                             /* Sequence number */
                                 CONST_CAST(char*,argv[0]),        /* Action */
                                 CONST_CAST(char*,argv[1]),        /* IP Protocol */
                                 CONST_CAST(char*,argv[2]),        /* Source IP */
                                 NULL,                             /* Source Port Operator */
                                 NULL,                             /* Source Port 1 */
                                 NULL,                             /* Source Port 2 */
                                 CONST_CAST(char*,argv[3]),        /* Destination IP */
                                 NULL,                             /* Destination Port Operator */
                                 NULL,                             /* Destination Port 1 */
                                 NULL,                             /* Destination Port 2 */
                                 CONST_CAST(char*,argv[4]),        /* Log */
                                 CONST_CAST(char*,argv[5]),        /* Count */
                                 NULL);                            /* Comment */
}

/**
 * Action routine for setting an ACE with a source port operator specified
 * without a sequence number
 */
DEFUN (cli_access_list_entry_src_port_op_no_seq,
       cli_access_list_entry_src_port_op_no_seq_cmd,
       /* start of cmdstr, broken up to help readability */
       ACE_ACTION_CMDSTR
       ACE_PORT_PROTOCOLS_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_PORT_OPER_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_ADDITIONAL_OPTIONS_CMDSTR
       , /* end of cmdstr, comment to avoid accidental comma loss */

       /* helpstr, newline delimited */
       ACE_ACTION_HELPSTR
       ACE_PORT_PROTOCOLS_HELPSTR
       ACE_SRC_IP_ADDRESS_HELPSTR
       ACE_SRC_PORT_OPER_HELPSTR
       ACE_DST_IP_ADDRESS_HELPSTR
       ACE_ADDITIONAL_OPTIONS_HELPSTR
      )
{
    return cli_create_update_ace(CONST_CAST(char*,vty->index),     /* Type */
                                 CONST_CAST(char*,vty->index_sub), /* Name */
                                 NULL,                             /* Sequence number */
                                 CONST_CAST(char*,argv[0]),        /* Action */
                                 CONST_CAST(char*,argv[1]),        /* IP Protocol */
                                 CONST_CAST(char*,argv[2]),        /* Source IP */
                                 CONST_CAST(char*,argv[3]),        /* Source Port Operator */
                                 CONST_CAST(char*,argv[4]),        /* Source Port 1 */
                                 NULL,                             /* Source Port 2 */
                                 CONST_CAST(char*,argv[5]),        /* Destination IP */
                                 NULL,                             /* Destination Port Operator */
                                 NULL,                             /* Destination Port 1 */
                                 NULL,                             /* Destination Port 2 */
                                 CONST_CAST(char*,argv[6]),        /* Log */
                                 CONST_CAST(char*,argv[7]),        /* Count */
                                 NULL);                            /* Comment */
}

/**
 * Action routine for setting an ACE with a source port range specified
 * without a sequence number
 */
DEFUN (cli_access_list_entry_src_port_range_no_seq,
       cli_access_list_entry_src_port_range_no_seq_cmd,
       /* start of cmdstr, broken up to help readability */
       ACE_ACTION_CMDSTR
       ACE_PORT_PROTOCOLS_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_PORT_RANGE_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_ADDITIONAL_OPTIONS_CMDSTR
       , /* end of cmdstr, comment to avoid accidental comma loss */

       /* helpstr, newline delimited */
       ACE_ACTION_HELPSTR
       ACE_PORT_PROTOCOLS_HELPSTR
       ACE_SRC_IP_ADDRESS_HELPSTR
       ACE_SRC_PORT_RANGE_HELPSTR
       ACE_DST_IP_ADDRESS_HELPSTR
       ACE_ADDITIONAL_OPTIONS_HELPSTR
      )
{
    return cli_create_update_ace(CONST_CAST(char*,vty->index),     /* Type */
                                 CONST_CAST(char*,vty->index_sub), /* Name */
                                 NULL,                             /* Sequence number */
                                 CONST_CAST(char*,argv[0]),        /* Action */
                                 CONST_CAST(char*,argv[1]),        /* IP Protocol */
                                 CONST_CAST(char*,argv[2]),        /* Source IP */
                                 CONST_CAST(char*,argv[3]),        /* Source Port Operator */
                                 CONST_CAST(char*,argv[4]),        /* Source Port 1 */
                                 CONST_CAST(char*,argv[5]),        /* Source Port 2 */
                                 CONST_CAST(char*,argv[6]),        /* Destination IP */
                                 NULL,                             /* Destination Port Operator */
                                 NULL,                             /* Destination Port 1 */
                                 NULL,                             /* Destination Port 2 */
                                 CONST_CAST(char*,argv[7]),        /* Log */
                                 CONST_CAST(char*,argv[8]),        /* Count */
                                 NULL);                            /* Comment */
}

/**
 * Action routine for setting an ACE with a destination port operator specified
 * without a sequence number
 */
DEFUN (cli_access_list_entry_dst_port_op_no_seq,
       cli_access_list_entry_dst_port_op_no_seq_cmd,
       /* start of cmdstr, broken up to help readability */
       ACE_ACTION_CMDSTR
       ACE_PORT_PROTOCOLS_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_PORT_OPER_CMDSTR
       ACE_ADDITIONAL_OPTIONS_CMDSTR
       , /* end of cmdstr, comment to avoid accidental comma loss */

       /* helpstr, newline delimited */
       ACE_ACTION_HELPSTR
       ACE_PORT_PROTOCOLS_HELPSTR
       ACE_SRC_IP_ADDRESS_HELPSTR
       ACE_DST_IP_ADDRESS_HELPSTR
       ACE_DST_PORT_OPER_HELPSTR
       ACE_ADDITIONAL_OPTIONS_HELPSTR
      )
{
    return cli_create_update_ace(CONST_CAST(char*,vty->index),     /* Type */
                                 CONST_CAST(char*,vty->index_sub), /* Name */
                                 NULL,                             /* Sequence number */
                                 CONST_CAST(char*,argv[0]),        /* Action */
                                 CONST_CAST(char*,argv[1]),        /* IP Protocol */
                                 CONST_CAST(char*,argv[2]),        /* Source IP */
                                 NULL,                             /* Source Port Operator */
                                 NULL,                             /* Source Port 1 */
                                 NULL,                             /* Source Port 2 */
                                 CONST_CAST(char*,argv[3]),        /* Destination IP */
                                 CONST_CAST(char*,argv[4]),        /* Destination Port Operator */
                                 CONST_CAST(char*,argv[5]),        /* Destination Port 1 */
                                 NULL,                             /* Destination Port 2 */
                                 CONST_CAST(char*,argv[6]),        /* Log */
                                 CONST_CAST(char*,argv[7]),        /* Count */
                                 NULL);                            /* Comment */
}

/**
 * Action routine for setting an ACE with a destination port range specified
 * without a sequence number
 */
DEFUN (cli_access_list_entry_dst_port_range_no_seq,
       cli_access_list_entry_dst_port_range_no_seq_cmd,
       /* start of cmdstr, broken up to help readability */
       ACE_ACTION_CMDSTR
       ACE_PORT_PROTOCOLS_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_PORT_RANGE_CMDSTR
       ACE_ADDITIONAL_OPTIONS_CMDSTR
       , /* end of cmdstr, comment to avoid accidental comma loss */

       /* helpstr, newline delimited */
       ACE_ACTION_HELPSTR
       ACE_PORT_PROTOCOLS_HELPSTR
       ACE_SRC_IP_ADDRESS_HELPSTR
       ACE_DST_IP_ADDRESS_HELPSTR
       ACE_DST_PORT_RANGE_HELPSTR
       ACE_ADDITIONAL_OPTIONS_HELPSTR
      )
{
    return cli_create_update_ace(CONST_CAST(char*,vty->index),     /* Type */
                                 CONST_CAST(char*,vty->index_sub), /* Name */
                                 NULL,                             /* Sequence number */
                                 CONST_CAST(char*,argv[0]),        /* Action */
                                 CONST_CAST(char*,argv[1]),        /* IP Protocol */
                                 CONST_CAST(char*,argv[2]),        /* Source IP */
                                 NULL,                             /* Source Port Operator */
                                 NULL,                             /* Source Port 1 */
                                 NULL,                             /* Source Port 2 */
                                 CONST_CAST(char*,argv[3]),        /* Destination IP */
                                 CONST_CAST(char*,argv[4]),        /* Destination Port Operator */
                                 CONST_CAST(char*,argv[5]),        /* Destination Port 1 */
                                 CONST_CAST(char*,argv[6]),        /* Destination Port 2 */
                                 CONST_CAST(char*,argv[7]),        /* Log */
                                 CONST_CAST(char*,argv[8]),        /* Count */
                                 NULL);                            /* Comment */
}

/**
 * Action routine for setting an ACE with both source and destination port
 * operators specified without a sequence number
 */
DEFUN (cli_access_list_entry_src_port_op_dst_port_op_no_seq,
       cli_access_list_entry_src_port_op_dst_port_op_no_seq_cmd,
       /* start of cmdstr, broken up to help readability */
       ACE_ACTION_CMDSTR
       ACE_PORT_PROTOCOLS_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_PORT_OPER_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_PORT_OPER_CMDSTR
       ACE_ADDITIONAL_OPTIONS_CMDSTR
       , /* end of cmdstr, comment to avoid accidental comma loss */

       /* helpstr, newline delimited */
       ACE_ACTION_HELPSTR
       ACE_PORT_PROTOCOLS_HELPSTR
       ACE_SRC_IP_ADDRESS_HELPSTR
       ACE_SRC_PORT_OPER_HELPSTR
       ACE_DST_IP_ADDRESS_HELPSTR
       ACE_DST_PORT_OPER_HELPSTR
       ACE_ADDITIONAL_OPTIONS_HELPSTR
      )
{
    return cli_create_update_ace(CONST_CAST(char*,vty->index),     /* Type */
                                 CONST_CAST(char*,vty->index_sub), /* Name */
                                 NULL,                             /* Sequence number */
                                 CONST_CAST(char*,argv[0]),        /* Action */
                                 CONST_CAST(char*,argv[1]),        /* IP Protocol */
                                 CONST_CAST(char*,argv[2]),        /* Source IP */
                                 CONST_CAST(char*,argv[3]),        /* Source Port Operator */
                                 CONST_CAST(char*,argv[4]),        /* Source Port 1 */
                                 NULL,                             /* Source Port 2 */
                                 CONST_CAST(char*,argv[5]),        /* Destination IP */
                                 CONST_CAST(char*,argv[6]),        /* Destination Port Operator */
                                 CONST_CAST(char*,argv[7]),        /* Destination Port 1 */
                                 NULL,                             /* Destination Port 2 */
                                 CONST_CAST(char*,argv[8]),        /* Log */
                                 CONST_CAST(char*,argv[9]),        /* Count */
                                 NULL);                            /* Comment */
}

/**
 * Action routine for setting an ACE with both source and destination port
 * ranges specified without a sequence number
 */
DEFUN (cli_access_list_entry_src_port_range_dst_port_range_no_seq,
       cli_access_list_entry_src_port_range_dst_port_range_no_seq_cmd,
       /* start of cmdstr, broken up to help readability */
       ACE_ACTION_CMDSTR
       ACE_PORT_PROTOCOLS_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_PORT_RANGE_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_PORT_RANGE_CMDSTR
       ACE_ADDITIONAL_OPTIONS_CMDSTR
       , /* end of cmdstr, comment to avoid accidental comma loss */

       /* helpstr, newline delimited */
       ACE_ACTION_HELPSTR
       ACE_PORT_PROTOCOLS_HELPSTR
       ACE_SRC_IP_ADDRESS_HELPSTR
       ACE_SRC_PORT_RANGE_HELPSTR
       ACE_DST_IP_ADDRESS_HELPSTR
       ACE_DST_PORT_RANGE_HELPSTR
       ACE_ADDITIONAL_OPTIONS_HELPSTR
      )
{
    return cli_create_update_ace(CONST_CAST(char*,vty->index),     /* Type */
                                 CONST_CAST(char*,vty->index_sub), /* Name */
                                 NULL,                             /* Sequence number */
                                 CONST_CAST(char*,argv[0]),        /* Action */
                                 CONST_CAST(char*,argv[1]),        /* IP Protocol */
                                 CONST_CAST(char*,argv[2]),        /* Source IP */
                                 CONST_CAST(char*,argv[3]),        /* Source Port Operator */
                                 CONST_CAST(char*,argv[4]),        /* Source Port 1 */
                                 CONST_CAST(char*,argv[5]),        /* Source Port 2 */
                                 CONST_CAST(char*,argv[6]),        /* Destination IP */
                                 CONST_CAST(char*,argv[7]),        /* Destination Port Operator */
                                 CONST_CAST(char*,argv[8]),        /* Destination Port 1 */
                                 CONST_CAST(char*,argv[9]),        /* Destination Port 2 */
                                 CONST_CAST(char*,argv[10]),       /* Log */
                                 CONST_CAST(char*,argv[11]),       /* Count */
                                 NULL);                            /* Comment */
}

/**
 * Action routine for setting an ACE with source port operator and destination
 * port range specified without a sequence number
 */
DEFUN (cli_access_list_entry_src_port_op_dst_port_range_no_seq,
       cli_access_list_entry_src_port_op_dst_port_range_no_seq_cmd,
       /* start of cmdstr, broken up to help readability */
       ACE_ACTION_CMDSTR
       ACE_PORT_PROTOCOLS_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_PORT_OPER_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_PORT_RANGE_CMDSTR
       ACE_ADDITIONAL_OPTIONS_CMDSTR
       , /* end of cmdstr, comment to avoid accidental comma loss */

       /* helpstr, newline delimited */
       ACE_ACTION_HELPSTR
       ACE_PORT_PROTOCOLS_HELPSTR
       ACE_SRC_IP_ADDRESS_HELPSTR
       ACE_SRC_PORT_OPER_HELPSTR
       ACE_DST_IP_ADDRESS_HELPSTR
       ACE_DST_PORT_RANGE_HELPSTR
       ACE_ADDITIONAL_OPTIONS_HELPSTR
      )
{
    return cli_create_update_ace(CONST_CAST(char*,vty->index),     /* Type */
                                 CONST_CAST(char*,vty->index_sub), /* Name */
                                 NULL,                             /* Sequence number */
                                 CONST_CAST(char*,argv[0]),        /* Action */
                                 CONST_CAST(char*,argv[1]),        /* IP Protocol */
                                 CONST_CAST(char*,argv[2]),        /* Source IP */
                                 CONST_CAST(char*,argv[3]),        /* Source Port Operator */
                                 CONST_CAST(char*,argv[4]),        /* Source Port 1 */
                                 NULL,                             /* Source Port 2 */
                                 CONST_CAST(char*,argv[5]),        /* Destination IP */
                                 CONST_CAST(char*,argv[6]),        /* Destination Port Operator */
                                 CONST_CAST(char*,argv[7]),        /* Destination Port 1 */
                                 CONST_CAST(char*,argv[8]),        /* Destination Port 2 */
                                 CONST_CAST(char*,argv[9]),        /* Log */
                                 CONST_CAST(char*,argv[10]),       /* Count */
                                 NULL);                            /* Comment */
}

/**
 * Action routine for setting an ACE with source port range and destination
 * port operator specified without a sequence number
 */
DEFUN (cli_access_list_entry_src_port_range_dst_port_op_no_seq,
       cli_access_list_entry_src_port_range_dst_port_op_no_seq_cmd,
       /* start of cmdstr, broken up to help readability */
       ACE_ACTION_CMDSTR
       ACE_PORT_PROTOCOLS_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_PORT_RANGE_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_PORT_OPER_CMDSTR
       ACE_ADDITIONAL_OPTIONS_CMDSTR
       , /* end of cmdstr, comment to avoid accidental comma loss */

       /* helpstr, newline delimited */
       ACE_ACTION_HELPSTR
       ACE_PORT_PROTOCOLS_HELPSTR
       ACE_SRC_IP_ADDRESS_HELPSTR
       ACE_SRC_PORT_RANGE_HELPSTR
       ACE_DST_IP_ADDRESS_HELPSTR
       ACE_DST_PORT_OPER_HELPSTR
       ACE_ADDITIONAL_OPTIONS_HELPSTR
      )
{
    return cli_create_update_ace(CONST_CAST(char*,vty->index),     /* Type */
                                 CONST_CAST(char*,vty->index_sub), /* Name */
                                 NULL,                             /* Sequence number */
                                 CONST_CAST(char*,argv[0]),        /* Action */
                                 CONST_CAST(char*,argv[1]),        /* IP Protocol */
                                 CONST_CAST(char*,argv[2]),        /* Source IP */
                                 CONST_CAST(char*,argv[3]),        /* Source Port Operator */
                                 CONST_CAST(char*,argv[4]),        /* Source Port 1 */
                                 CONST_CAST(char*,argv[5]),        /* Source Port 2 */
                                 CONST_CAST(char*,argv[6]),        /* Destination IP */
                                 CONST_CAST(char*,argv[7]),        /* Destination Port Operator */
                                 CONST_CAST(char*,argv[8]),        /* Destination Port 1 */
                                 NULL,                             /* Destination Port 2 */
                                 CONST_CAST(char*,argv[9]),        /* Log */
                                 CONST_CAST(char*,argv[10]),       /* Count */
                                 NULL);                            /* Comment */
}

/**
 * Action routine for setting an ACE comment
 */
DEFUN (cli_access_list_entry_comment,
       cli_access_list_entry_comment_cmd,
       /* start of cmdstr, broken up to help readability */
       ACE_SEQ_CMDSTR
       ACE_COMMENT_CMDSTR
       ACE_COMMENT_TEXT_CMDSTR
       , /* end of cmdstr, comment to avoid accidental comma loss */

       /* helpstr, newline delimited */
       ACE_SEQ_HELPSTR
       ACE_COMMENT_HELPSTR
       ACE_COMMENT_TEXT_HELPSTR
      )
{
    /* To be freed after use */
    char *comment_text = argv_concat(argv, argc, 2);

    return cli_create_update_ace(CONST_CAST(char*,vty->index),     /* Type */
                                 CONST_CAST(char*,vty->index_sub), /* Name */
                                 CONST_CAST(char*,argv[0]),        /* Sequence number */
                                 CONST_CAST(char*,argv[1]),        /* Action */
                                 NULL,                             /* IP Protocol */
                                 NULL,                             /* Source IP */
                                 NULL,                             /* Source Port Operator */
                                 NULL,                             /* Source Port 1 */
                                 NULL,                             /* Source Port 2 */
                                 NULL,                             /* Destination IP */
                                 NULL,                             /* Destination Port Operator */
                                 NULL,                             /* Destination Port 1 */
                                 NULL,                             /* Destination Port 2 */
                                 NULL,                             /* Log */
                                 NULL,                             /* Count */
                                 comment_text);                    /* Comment */
}

/**
 * Action routine for setting an ACE comment without a sequence number
 */
DEFUN (cli_access_list_entry_comment_no_seq,
       cli_access_list_entry_comment_no_seq_cmd,
       /* start of cmdstr, broken up to help readability */
       ACE_COMMENT_CMDSTR
       ACE_COMMENT_TEXT_CMDSTR
       , /* end of cmdstr, comment to avoid accidental comma loss */

       /* helpstr, newline delimited */
       ACE_COMMENT_HELPSTR
       ACE_COMMENT_TEXT_HELPSTR
      )
{
    /* To be freed after use */
    char *comment_text = argv_concat(argv, argc, 1);

    return cli_create_update_ace(CONST_CAST(char*,vty->index),     /* Type */
                                 CONST_CAST(char*,vty->index_sub), /* Name */
                                 NULL,                             /* Sequence number */
                                 CONST_CAST(char*,argv[0]),        /* Action */
                                 NULL,                             /* IP Protocol */
                                 NULL,                             /* Source IP */
                                 NULL,                             /* Source Port Operator */
                                 NULL,                             /* Source Port 1 */
                                 NULL,                             /* Source Port 2 */
                                 NULL,                             /* Destination IP */
                                 NULL,                             /* Destination Port Operator */
                                 NULL,                             /* Destination Port 1 */
                                 NULL,                             /* Destination Port 2 */
                                 NULL,                             /* Log */
                                 NULL,                             /* Count */
                                 comment_text);                    /* Comment */
}

/**
 * Action routine for deleting an ACE comment
 */
DEFUN (cli_no_access_list_entry_comment,
       cli_no_access_list_entry_comment_cmd,
       /* start of cmdstr, broken up to help readability */
       "no "
       ACE_SEQ_CMDSTR
       ACE_COMMENT_CMDSTR
       , /* end of cmdstr, comment to avoid accidental comma loss */

       /* helpstr, newline delimited */
       NO_STR
       ACE_SEQ_HELPSTR
       ACE_COMMENT_HELPSTR
      )
{
    return cli_create_update_ace(CONST_CAST(char*,vty->index),     /* Type */
                                 CONST_CAST(char*,vty->index_sub), /* Name */
                                 CONST_CAST(char*,argv[0]),        /* Sequence number */
                                 CONST_CAST(char*,argv[1]),        /* Action */
                                 NULL,                             /* IP Protocol */
                                 NULL,                             /* Source IP */
                                 NULL,                             /* Source Port Operator */
                                 NULL,                             /* Source Port 1 */
                                 NULL,                             /* Source Port 2 */
                                 NULL,                             /* Destination IP */
                                 NULL,                             /* Destination Port Operator */
                                 NULL,                             /* Destination Port 1 */
                                 NULL,                             /* Destination Port 2 */
                                 NULL,                             /* Log */
                                 NULL,                             /* Count */
                                 NULL);                            /* Comment */
}

/* Can't delete an ACE comment without a sequence number, so no DEFUN for it */

/**
 * Alternate form that ignores additional tokens when deleting an ACE comment
 */
ALIAS (cli_no_access_list_entry_comment,
       cli_no_access_list_entry_comment_etc_cmd,
       "no "
       ACE_SEQ_CMDSTR
       ACE_COMMENT_CMDSTR
       ACE_ETC_CMDSTR
       , /* end of cmdstr, comment to avoid accidental comma loss */

       /* helpstr, newline delimited */
       NO_STR
       ACE_SEQ_HELPSTR
       ACE_COMMENT_HELPSTR
       ACE_ETC_HELPSTR
      )

/**
 * Action routine for deleting an ACE
 */
DEFUN (cli_no_access_list_entry,
       cli_no_access_list_entry_cmd,
       "no " ACE_SEQ_CMDSTR,
       NO_STR
       ACE_SEQ_HELPSTR
      )
{
    return cli_delete_ace(CONST_CAST(char*,vty->index),     /* Type */
                          CONST_CAST(char*,vty->index_sub), /* Name */
                          CONST_CAST(char*,argv[0]));       /* Sequence number */
}

/**
 * Alternate form that ignores additional tokens when deleting an ACE
 */
ALIAS (cli_no_access_list_entry,
       cli_no_access_list_entry_etc_cmd,
       "no "
       ACE_SEQ_CMDSTR
       ACE_ETC_CMDSTR
       , /* end of cmdstr, comment to avoid accidental comma loss */

       /* helpstr, newline delimited */
       NO_STR
       ACE_SEQ_HELPSTR
       ACE_ETC_HELPSTR
      )

/**
 * Action routine for showing applications of ACLs
 */
DEFUN (cli_show_access_list_applied, cli_show_access_list_applied_cmd,
       "show access-list (interface|vlan) ID { ip | in | config }",
       SHOW_STR
       ACL_STR
       ACL_INTERFACE_STR
       ACL_VLAN_STR
       ACL_INTERFACE_ID_STR
       ACL_IP_STR
       ACL_IN_STR
       ACL_CFG_STR
      )
{
    const char ipv4_str[] = "ipv4";
    const char *type_str;
    if (argv[2] && !strcmp(argv[2], "ip")) {
        type_str = ipv4_str;
    } else {
        type_str = argv[2];
    }
    return cli_print_applied_acls(CONST_CAST(char*,argv[0]),  /* interface type */
                                  CONST_CAST(char*,argv[1]),  /* interface id */
                                  CONST_CAST(char*,type_str), /* type */
                                  CONST_CAST(char*,argv[3]),  /* direction */
                                  CONST_CAST(char*,argv[4])); /* config */
}

/**
 * Action routine for applying an ACL to an interface
 */
DEFUN (cli_apply_access_list, cli_apply_access_list_cmd,
       "apply access-list (ip) NAME (in)",
       ACL_APPLY_STR
       ACL_STR
       ACL_IP_STR
       ACL_NAME_STR
       ACL_IN_STR
      )
{
    const char vlan_str[] = "vlan";
    const char interface_str[] = "interface";
    const char *interface_type_str;
    const char ipv4_str[] = "ipv4";
    const char *type_str;

    if (vty->node == VLAN_NODE) {
        interface_type_str = vlan_str;
    } else if (vty->node == INTERFACE_NODE) {
        interface_type_str = interface_str;
    } else {
        interface_type_str = NULL;
    }
    if (argv[0] && !strcmp(argv[0], "ip")) {
        type_str = ipv4_str;
    } else {
        type_str = argv[0];
    }

    return cli_apply_acl(interface_type_str,           /* interface type */
                         CONST_CAST(char*,vty->index), /* interface id */
                         type_str,                     /* type */
                         CONST_CAST(char*,argv[1]),    /* name */
                         CONST_CAST(char*,argv[2]));   /* direction */
}

/**
 * Action routine for un-applying an ACL from an interface
 */
DEFUN (cli_no_apply_access_list, cli_no_apply_access_list_cmd,
       "no apply access-list (ip) NAME (in)",
       NO_STR
       ACL_APPLY_STR
       ACL_STR
       ACL_IP_STR
       ACL_NAME_STR
       ACL_IN_STR
      )
{
    const char vlan_str[] = "vlan";
    const char interface_str[] = "interface";
    const char *interface_type_str;
    const char ipv4_str[] = "ipv4";
    const char *type_str;

    if (vty->node == VLAN_NODE) {
        interface_type_str = vlan_str;
    } else if (vty->node == INTERFACE_NODE) {
        interface_type_str = interface_str;
    } else {
        interface_type_str = NULL;
    }
    if (argv[0] && !strcmp(argv[0], "ip")) {
        type_str = ipv4_str;
    } else {
        type_str = argv[0];
    }

    return cli_unapply_acl(interface_type_str,           /* interface type */
                           CONST_CAST(char*,vty->index), /* interface id */
                           type_str,                     /* type */
                           CONST_CAST(char*,argv[1]),    /* name */
                           CONST_CAST(char*,argv[2]));   /* direction */
}

/**
 * Action routine for showing ACL statistics on a specified interface
 */
DEFUN (cli_show_access_list_hitcounts,
       cli_show_access_list_hitcounts_cmd,
       "show access-list hitcounts (ip) NAME (interface|vlan) ID { in }",
       SHOW_STR
       ACL_STR
       ACL_HITCOUNTS_STR
       ACL_IP_STR
       ACL_NAME_STR
       ACL_INTERFACE_STR
       ACL_VLAN_STR
       ACL_INTERFACE_ID_STR
       ACL_IN_STR
      )
{
    const char ipv4_str[] = "ipv4";
    const char *type_str;
    if (argv[0] && !strcmp(argv[0], "ip")) {
        type_str = ipv4_str;
    } else {
        type_str = argv[0];
    }
    return cli_print_acl_statistics(CONST_CAST(char*,type_str), /* type */
                                    CONST_CAST(char*,argv[1]),  /* name */
                                    CONST_CAST(char*,argv[2]),  /* interface type */
                                    CONST_CAST(char*,argv[3]),  /* interface id */
                                    CONST_CAST(char*,argv[4])); /* direction */
}

/**
 * Action routine for showing ACL statistics on all applied interfaces
 */
DEFUN (cli_show_access_list_hitcounts_all,
       cli_show_access_list_hitcounts_all_cmd,
       "show access-list hitcounts (ip) NAME",
       SHOW_STR
       ACL_STR
       ACL_HITCOUNTS_STR
       ACL_IP_STR
       ACL_NAME_STR
      )
{
    const char ipv4_str[] = "ipv4";
    const char *type_str;
    if (argv[0] && !strcmp(argv[0], "ip")) {
        type_str = ipv4_str;
    } else {
        type_str = argv[0];
    }
    return cli_print_acl_statistics(CONST_CAST(char*,type_str), /* type */
                                    CONST_CAST(char*,argv[1]),  /* name */
                                    NULL,                       /* interface type */
                                    NULL,                       /* interface id */
                                    NULL);                      /* direction */
}

/**
 * Action routine for clearing ACL statistics on a specified interface
 */
DEFUN (cli_clear_access_list_hitcounts,
       cli_clear_access_list_hitcounts_cmd,
       "clear access-list hitcounts (ip) NAME (interface|vlan) ID { in }",
       SHOW_STR
       ACL_STR
       ACL_HITCOUNTS_STR
       ACL_IP_STR
       ACL_NAME_STR
       ACL_INTERFACE_STR
       ACL_VLAN_STR
       ACL_INTERFACE_ID_STR
       ACL_IN_STR
      )
{
    const char ipv4_str[] = "ipv4";
    const char *type_str;

    if (argv[0] && !strcmp(argv[0], "ip")) {
        type_str = ipv4_str;
    } else {
        type_str = argv[0];
    }

    return cli_clear_acl_statistics(CONST_CAST(char*,type_str), /* type */
                                    CONST_CAST(char*,argv[1]),  /* name */
                                    CONST_CAST(char*,argv[2]),  /* interface type */
                                    CONST_CAST(char*,argv[3]),  /* interface id */
                                    CONST_CAST(char*,argv[4])); /* direction */
}

/**
 * Action routine for clearing all ACL statistics on all interfaces
 */
DEFUN (cli_clear_access_list_hitcounts_all,
       cli_clear_access_list_hitcounts_all_cmd,
       "clear access-list hitcounts all { in }",
       CLEAR_STR
       ACL_STR
       ACL_HITCOUNTS_STR
       ACL_ALL_STR
       ACL_IN_STR
      )
{
    return cli_clear_acl_statistics(NULL,                       /* type */
                                    NULL,                       /* name */
                                    NULL,                       /* interface type */
                                    NULL,                       /* interface id */
                                    CONST_CAST(char*,argv[0])); /* direction */
}

/**
 * Action routine for setting ACL log timer to a specified value (or default)
 */
DEFUN (cli_access_list_log_timer, cli_access_list_log_timer_cmd,
       "access-list log-timer (default|<" ACL_LOG_TIMER_MIN "-" ACL_LOG_TIMER_MAX ">)",
       ACL_STR
       "Set ACL log timer length (frequency)\n"
       "Default value (" ACL_LOG_TIMER_DEFAULT " seconds)\n"
       "Specify value (in seconds)\n"
      )
{
    return cli_set_acl_log_timer(CONST_CAST(char*,argv[0])); /* timer_value */
}

/* = Initialization = */

/**
 * Prompt string when in access-list context
 */
static struct cmd_node access_list_node = {
    ACCESS_LIST_NODE,
    "%s(config-acl)# "
};

/**
 * Initialize ACL OVSDB tables, columns
 */
static void
access_list_ovsdb_init(void)
{
    /* acls column in System table */
    ovsdb_idl_add_column(idl, &ovsrec_system_col_acls);

    /* ACL table, columns */
    ovsdb_idl_add_table(idl, &ovsrec_table_acl);
    ovsdb_idl_add_column(idl, &ovsrec_acl_col_name);
    ovsdb_idl_add_column(idl, &ovsrec_acl_col_list_type);
    ovsdb_idl_add_column(idl, &ovsrec_acl_col_cfg_aces);
    ovsdb_idl_add_column(idl, &ovsrec_acl_col_cfg_version);
    ovsdb_idl_add_column(idl, &ovsrec_acl_col_cur_aces);
    ovsdb_idl_add_column(idl, &ovsrec_acl_col_in_progress_aces);
    ovsdb_idl_add_column(idl, &ovsrec_acl_col_status);

    /* ACL_Entry table, columns */
    ovsdb_idl_add_table(idl, &ovsrec_table_acl_entry);
    ovsdb_idl_add_column(idl, &ovsrec_acl_entry_col_action);
    ovsdb_idl_add_column(idl, &ovsrec_acl_entry_col_protocol);
    ovsdb_idl_add_column(idl, &ovsrec_acl_entry_col_src_ip);
    ovsdb_idl_add_column(idl, &ovsrec_acl_entry_col_src_l4_port_min);
    ovsdb_idl_add_column(idl, &ovsrec_acl_entry_col_src_l4_port_max);
    ovsdb_idl_add_column(idl, &ovsrec_acl_entry_col_src_l4_port_range_reverse);
    ovsdb_idl_add_column(idl, &ovsrec_acl_entry_col_dst_ip);
    ovsdb_idl_add_column(idl, &ovsrec_acl_entry_col_dst_l4_port_min);
    ovsdb_idl_add_column(idl, &ovsrec_acl_entry_col_dst_l4_port_max);
    ovsdb_idl_add_column(idl, &ovsrec_acl_entry_col_dst_l4_port_range_reverse);
    ovsdb_idl_add_column(idl, &ovsrec_acl_entry_col_log);
    ovsdb_idl_add_column(idl, &ovsrec_acl_entry_col_count);
    ovsdb_idl_add_column(idl, &ovsrec_acl_entry_col_comment);

    /* ACL columns in Port table */
    ovsdb_idl_add_table(idl, &ovsrec_table_port);
    ovsdb_idl_add_column(idl, &ovsrec_port_col_aclv4_in_applied);
    ovsdb_idl_add_column(idl, &ovsrec_port_col_aclv4_in_cfg);
    ovsdb_idl_add_column(idl, &ovsrec_port_col_aclv4_in_cfg_version);
    ovsdb_idl_add_column(idl, &ovsrec_port_col_aclv4_in_statistics);
    ovsdb_idl_add_column(idl, &ovsrec_port_col_aclv4_in_status);

    /* ACL columns in VLAN table */
    ovsdb_idl_add_table(idl, &ovsrec_table_vlan);
    ovsdb_idl_add_column(idl, &ovsrec_vlan_col_aclv4_in_applied);
    ovsdb_idl_add_column(idl, &ovsrec_vlan_col_aclv4_in_cfg);
    ovsdb_idl_add_column(idl, &ovsrec_vlan_col_aclv4_in_cfg_version);
    ovsdb_idl_add_column(idl, &ovsrec_vlan_col_aclv4_in_statistics);
    ovsdb_idl_add_column(idl, &ovsrec_vlan_col_aclv4_in_status);
}

/**
 * Install the CLI action routines for ACL
 */
static void
access_list_vty_init(void)
{
    install_element(CONFIG_NODE, &cli_access_list_cmd);
    install_element(CONFIG_NODE, &cli_no_access_list_cmd);
    install_element(CONFIG_NODE, &cli_access_list_resequence_cmd);

    install_element(ENABLE_NODE, &cli_show_access_list_cmd);
    install_element(ENABLE_NODE, &cli_show_access_list_type_cmd);
    install_element(ENABLE_NODE, &cli_show_access_list_type_name_cmd);
    install_element(VIEW_NODE, &cli_show_access_list_cmd);
    install_element(VIEW_NODE, &cli_show_access_list_type_cmd);
    install_element(VIEW_NODE, &cli_show_access_list_type_name_cmd);

    install_element(ACCESS_LIST_NODE, &cli_access_list_entry_cmd);
    install_element(ACCESS_LIST_NODE, &cli_access_list_entry_src_port_op_cmd);
    install_element(ACCESS_LIST_NODE, &cli_access_list_entry_src_port_range_cmd);
    install_element(ACCESS_LIST_NODE, &cli_access_list_entry_dst_port_op_cmd);
    install_element(ACCESS_LIST_NODE, &cli_access_list_entry_dst_port_range_cmd);
    install_element(ACCESS_LIST_NODE, &cli_access_list_entry_src_port_op_dst_port_op_cmd);
    install_element(ACCESS_LIST_NODE, &cli_access_list_entry_src_port_range_dst_port_range_cmd);
    install_element(ACCESS_LIST_NODE, &cli_access_list_entry_src_port_op_dst_port_range_cmd);
    install_element(ACCESS_LIST_NODE, &cli_access_list_entry_src_port_range_dst_port_op_cmd);

    install_element(ACCESS_LIST_NODE, &cli_access_list_entry_no_seq_cmd);
    install_element(ACCESS_LIST_NODE, &cli_access_list_entry_src_port_op_no_seq_cmd);
    install_element(ACCESS_LIST_NODE, &cli_access_list_entry_src_port_range_no_seq_cmd);
    install_element(ACCESS_LIST_NODE, &cli_access_list_entry_dst_port_op_no_seq_cmd);
    install_element(ACCESS_LIST_NODE, &cli_access_list_entry_dst_port_range_no_seq_cmd);
    install_element(ACCESS_LIST_NODE, &cli_access_list_entry_src_port_op_dst_port_op_no_seq_cmd);
    install_element(ACCESS_LIST_NODE, &cli_access_list_entry_src_port_range_dst_port_range_no_seq_cmd);
    install_element(ACCESS_LIST_NODE, &cli_access_list_entry_src_port_op_dst_port_range_no_seq_cmd);
    install_element(ACCESS_LIST_NODE, &cli_access_list_entry_src_port_range_dst_port_op_no_seq_cmd);

    install_element(ACCESS_LIST_NODE, &cli_access_list_entry_comment_cmd);
    install_element(ACCESS_LIST_NODE, &cli_access_list_entry_comment_no_seq_cmd);
    install_element(ACCESS_LIST_NODE, &cli_no_access_list_entry_comment_cmd);
    install_element(ACCESS_LIST_NODE, &cli_no_access_list_entry_comment_etc_cmd);

    install_element(ACCESS_LIST_NODE, &cli_no_access_list_entry_cmd);
    install_element(ACCESS_LIST_NODE, &cli_no_access_list_entry_etc_cmd);

    install_element(ENABLE_NODE, &cli_show_access_list_applied_cmd);
    install_element(VIEW_NODE, &cli_show_access_list_applied_cmd);

    install_element(INTERFACE_NODE, &cli_apply_access_list_cmd);
    install_element(INTERFACE_NODE, &cli_no_apply_access_list_cmd);
    install_element(VLAN_NODE, &cli_apply_access_list_cmd);
    install_element(VLAN_NODE, &cli_no_apply_access_list_cmd);

    install_element(ENABLE_NODE, &cli_show_access_list_hitcounts_cmd);
    install_element(ENABLE_NODE, &cli_show_access_list_hitcounts_all_cmd);
    install_element(VIEW_NODE, &cli_show_access_list_hitcounts_cmd);
    install_element(VIEW_NODE, &cli_show_access_list_hitcounts_all_cmd);
    install_element(ENABLE_NODE, &cli_clear_access_list_hitcounts_cmd);
    install_element(ENABLE_NODE, &cli_clear_access_list_hitcounts_all_cmd);

    install_element(CONFIG_NODE, &cli_access_list_log_timer_cmd);

    install_element(ACCESS_LIST_NODE, &config_exit_cmd);
    install_element(ACCESS_LIST_NODE, &config_quit_cmd);
    install_element(ACCESS_LIST_NODE, &config_end_cmd);
}

/* = "show running-configuration" Callbacks = */

/**
 * Callback routine for access-list (ACL) show running-config handler
 *
 * @param  p_private Void pointer for holding address of vtysh_ovsdb_cbmsg_ptr
 *                   structure object
 *
 * @return           e_vtysh_ok on success
 *
 * @sa print_acl_config A similar function that uses a different print method
 */
static vtysh_ret_val
show_run_access_list_callback(void *p_private)
{
    vtysh_ovsdb_cbmsg_ptr p_msg = (vtysh_ovsdb_cbmsg *) p_private;
    const struct ovsrec_system *ovs;
    const struct ovsrec_acl *acl_row;
    char *ace_str;
    int i;

    /* Get System table */
    ovs = ovsrec_system_first(idl);
    if (!ovs) {
        assert(0);
        return CMD_OVSDB_FAILURE;
    }

    /* Iterate over each ACL table entry */
    OVSREC_ACL_FOR_EACH(acl_row, p_msg->idl) {
        if (acl_row) {
            vtysh_ovsdb_cli_print(p_msg,
                                  "%s %s %s",
                                  "access-list",
                                  "ip",
                                  acl_row->name);
            /* Print each ACL entry as a single line (ala CLI input) */
            for (i = 0; i < acl_row->n_cur_aces; i ++) {
                /* If entry has or is a comment, print as its own line */
                if (acl_row->value_cur_aces[i]->comment) {
                    vtysh_ovsdb_cli_print(p_msg,
                                          "    %" PRId64 " comment %s",
                                          acl_row->key_cur_aces[i],
                                          acl_row->value_cur_aces[i]->comment);
                }
                if (acl_row->value_cur_aces[i]->action) {
                    ace_str = acl_entry_config_to_string(acl_row->key_cur_aces[i],
                                                         acl_row->value_cur_aces[i]);
                    vtysh_ovsdb_cli_print(p_msg, "    %s", ace_str);
                    free(ace_str);
                }
            }
        }
    }

    /* Print log timer configuration (if not default) */
    if (smap_get(&ovs->other_config, ACL_LOG_TIMER_STR))
    {
        vtysh_ovsdb_cli_print(p_msg, "access-list log-timer %s",
                              smap_get(&ovs->other_config, ACL_LOG_TIMER_STR));
    }
    return e_vtysh_ok;
}

/**
 * Callback routine for access-list show running-config subcontext handler
 *
 * @param  p_private Void pointer for holding address of vtysh_ovsdb_cbmsg_ptr
 *                   structure object
 *
 * @return           e_vtysh_ok on success
 */
static vtysh_ret_val
show_run_access_list_subcontext_callback(void *p_private)
{
    vtysh_ovsdb_cbmsg_ptr p_msg = (vtysh_ovsdb_cbmsg *) p_private;
    const struct ovsrec_vlan *vlan_row = NULL;
    const struct ovsrec_interface *interface_row = NULL;
    const struct ovsrec_port *port_row = NULL;

    /* Determine context type and subtype we were called for */
    if (p_msg->contextid == e_vtysh_vlan_context &&
        p_msg->clientid == e_vtysh_vlan_context_access_list) {
        vlan_row = (struct ovsrec_vlan *) p_msg->feature_row;
    } else if (p_msg->contextid == e_vtysh_interface_context &&
               p_msg->clientid == e_vtysh_interface_context_access_list) {
        interface_row = (struct ovsrec_interface *) p_msg->feature_row;
    } else {
        VLOG_ERR("%s called with unhandled contextid=%d clientid=%d",
                 __func__, p_msg->contextid, p_msg->clientid);
        return e_vtysh_error;
    }

    /* Print VLAN ACL, if any */
    if (vlan_row && vlan_row->aclv4_in_applied) {
        vtysh_ovsdb_cli_print(p_msg, "    apply access-list ip %s in",
                              vlan_row->aclv4_in_applied->name);
    }
    /* Print port ACL, if any (LAGs won't have interface name == port name) */
    if (interface_row) {
        port_row = get_port_by_name(interface_row->name);
        if (port_row && port_row->aclv4_in_applied) {
            vtysh_ovsdb_cli_print(p_msg, "    apply access-list ip %s in",
                                  port_row->aclv4_in_applied->name);
        }
    }
    return e_vtysh_ok;
}

/* = Public Interfaces = */

/**
 * Initialize context and database infrastructure for access-list
 */
void
cli_pre_init (void)
{
    install_node(&access_list_node, NULL);
    vtysh_install_default(ACCESS_LIST_NODE);

    access_list_ovsdb_init();
}

/**
 * Initialize access-list and related "show" vty commands
 */
void
cli_post_init (void)
{
    vtysh_ret_val retval;

    /* Register access-list and related commands */
    access_list_vty_init();

    /* Register show running-configuration callback */
    retval = install_show_run_config_context(
                    e_vtysh_access_list_context,
                    &show_run_access_list_callback,
                    NULL, NULL);
    if (e_vtysh_ok != retval) {
        vtysh_ovsdb_config_logmsg(VTYSH_OVSDB_CONFIG_ERR,
                    "unable to add access-list show running callback");
        assert(0);
        return;
    }

    /* Register port context show running-configuration command */
    retval = install_show_run_config_subcontext(
                    e_vtysh_interface_context,
                    e_vtysh_interface_context_access_list,
                    &show_run_access_list_subcontext_callback,
                    NULL, NULL);
    if (e_vtysh_ok != retval) {
        vtysh_ovsdb_config_logmsg(VTYSH_OVSDB_CONFIG_ERR,
                    "unable to add port access-list show running callback");
        assert(0);
        return;
    }

    /* Register vlan context show running-configuration command */
    retval = install_show_run_config_subcontext(
                    e_vtysh_vlan_context,
                    e_vtysh_vlan_context_access_list,
                    &show_run_access_list_subcontext_callback,
                    NULL, NULL);
    if (e_vtysh_ok != retval) {
        vtysh_ovsdb_config_logmsg(VTYSH_OVSDB_CONFIG_ERR,
                    "unable to add vlan access-list show running callback");
        assert(0);
        return;
    }
}
