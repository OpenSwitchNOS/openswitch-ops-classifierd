/****************************************************************************
 * (c) Copyright 2016 Hewlett Packard Enterprise Development LP
 *
 *    Licensed under the Apache License, Version 2.0 (the "License"); you may
 *    not use this file except in compliance with the License. You may obtain
 *    a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *    License for the specific language governing permissions and limitations
 *    under the License.
 *
 ***************************************************************************/

#include <vtysh/command.h>
#include <vtysh/memory.h>
#include <vtysh/vtysh.h>
#include <vtysh/vtysh_user.h>
#include <vtysh/vtysh_ovsdb_if.h>
#include <vtysh/vtysh_ovsdb_config.h>

#include <openvswitch/vlog.h>
#include <smap.h>
#include <json.h>

#include <vswitch-idl.h>
#include <ovsdb-idl.h>
#include <openswitch-idl.h>

#include "mirror_cli.h"

VLOG_DEFINE_THIS_MODULE(vtysh_mirror_cli);
extern struct ovsdb_idl *idl;

static char g_mirror_name[MAX_MIRROR_SESSION_NAME_LEN];



/* callback hook to support displaying mirrors details
 * for 'show running-config'
 */
vtysh_ret_val
cli_show_mirror_running_config_callback(void *p_private)
{

   //vtysh_ovsdb_cbmsg_ptr p_msg = (vtysh_ovsdb_cbmsg *) p_private;
   const struct ovsrec_mirror *mirror = NULL;
   const struct ovsrec_port *src_port = NULL;
   const struct ovsrec_port *dst_port = NULL;
   int n_dst_port, n_src_port = 0;
   bool any_both, both = false;
   bool *both_array = NULL;

   OVSREC_MIRROR_FOR_EACH (mirror, idl)
   {

      any_both = false;

      /* display name first */
      if(mirror->name) {
         vty_out(vty, "mirror session %s%s", mirror->name, VTY_NEWLINE);
      } else {
         /* mirror shouldn't exist w/out a name */
         return e_vtysh_error;
      }

      /* destination interface (one) */
      if (mirror->output_port && mirror->output_port->name) {
         vty_out(vty, "    destination interface %s%s", mirror->output_port->name, VTY_NEWLINE);
      }

      /* source interface (many)
       * A mirror can have multiple source ports, and each port's traffic can
       * be monitored inbound only, outbound only, or in both directions.
       * The following attempts to group, and display a given source port's
       * inbound/rx ports first, followed by outbound/tx, followed by 'both'.
       */
      /* any source rx ports to scan? */
      if (mirror->n_select_src_port > 0) {

         /* if there's any dst ports, there's a chance of 'both' condition,
          * so prep flag array
          */
         if (mirror->n_select_dst_port > 0) {
            both_array = calloc(mirror->n_select_dst_port, sizeof *both_array);
            if (NULL == both_array) {
               return e_vtysh_error;
            }
         }

         for (n_src_port=0; n_src_port < mirror->n_select_src_port; n_src_port++) {

            both = false;
            src_port = mirror->select_src_port[n_src_port];

            /* don't waste time scanning if there's no dst ports */
            if (mirror->n_select_dst_port > 0) {

               /* need to scan all dst ports to see if this src port is there,
                * i.e. both
                * */
               for (n_dst_port=0; n_dst_port < mirror->n_select_dst_port; n_dst_port++) {

                  dst_port = mirror->select_dst_port[n_dst_port];

                  if (strcmp(dst_port->name, src_port->name) == 0) {

                     both = true;
                     any_both = true;
                     /* if this port is also a destination, note this fact for
                      * 'both' designation
                      */
                     both_array[n_dst_port] = true;
                     break;
                  }
               }
            }

            if (!both) {
               vty_out(vty, "    source interface %s rx%s", src_port->name, VTY_NEWLINE);
            }
         }

      }

      /* any source tx ports to scan? */
      if (mirror->n_select_dst_port > 0) {

         for (n_dst_port=0; n_dst_port < mirror->n_select_dst_port; n_dst_port++ ) {

            dst_port = mirror->select_dst_port[n_dst_port];
            /* if no source rx ports, no 'both' potential */
            if (mirror->n_select_src_port == 0) {
               vty_out(vty, "    source interface %s tx%s", dst_port->name, VTY_NEWLINE);
               continue;

            } else {

               if (!both_array[n_dst_port]) {
                  vty_out(vty, "    source interface %s tx%s", dst_port->name, VTY_NEWLINE);
               }
            }
         }
      }

      if (any_both) {
         /* reuse, but invert the 'both' avoidance logic to display the 'both' ones */
         for (n_dst_port=0; n_dst_port < mirror->n_select_dst_port; n_dst_port++ ) {

            if (both_array[n_dst_port]) {
               dst_port = mirror->select_dst_port[n_dst_port];
               vty_out(vty, "    source interface %s both%s", dst_port->name, VTY_NEWLINE);
            }
         }
      }

      if (both_array) {
         free (both_array);
         both_array = NULL;
      }

      /* active/no shutdown */
      if (mirror->active && (*mirror->active == true)) {
         vty_out(vty, "    no shutdown%s", VTY_NEWLINE);
      }
   }
   return e_vtysh_ok;

}


/* the show vtysh command: 'show mirror [name]'
 * supplying a mirror name as argument prints details of * that mirror.
 * omitting a name arg prints a summary list of all configured mirrors.
 */
int
cli_show_mirror_exec (const char *mirror_arg)
{

   const struct ovsrec_mirror *mirror = NULL;
   const struct ovsrec_port *src_port = NULL;
   const struct ovsrec_port *dst_port = NULL;
   bool *both_array = NULL;
   bool both = false;
   int n_dst_port, n_src_port, found = 0;
   const char* mstate = NULL;
   const struct ovsdb_datum *datum = NULL;
   union ovsdb_atom atom;
   unsigned int index = 0;

   static char *mirror_statistics[] = { "tx_packets", "tx_bytes" };

   OVSREC_MIRROR_FOR_EACH (mirror, idl)
   {

      if (NULL != mirror_arg) {
         /* looking for specified mirror */
         if (strncmp(mirror_arg, mirror->name,
                (MAX_MIRROR_SESSION_NAME_LEN-1)) == 0) {
            found++;

            /* print mirror detail */
            vty_out(vty, " Mirror Session: %s%s", mirror->name, VTY_NEWLINE);

            mstate = smap_get (&mirror->mirror_status, "operation_state");
            vty_out(vty, " Status: %s%s", (mstate ? mstate : "new"),
                                                            VTY_NEWLINE);

            /* an array to flag which select_dst_ports are found to be 'both'
             * so we don't have to loop both src & dst ports twice */
            if (mirror->n_select_dst_port > 0) {
               both_array = calloc(mirror->n_select_dst_port, sizeof *both_array);
               if (NULL == both_array) {
                  /* TODO: error */
                  return 1;
               }
            }

            /* mirror receive source ports */
            if (mirror->n_select_src_port == 0) {
               vty_out(vty, " Source: interface rx none%s", VTY_NEWLINE);

            } else {

               for (n_src_port=0; n_src_port < mirror->n_select_src_port; n_src_port++) {

                  src_port = mirror->select_src_port[n_src_port];
                  both = false;
                  /* if this port is also a destination, note this fact */
                  for (n_dst_port=0; n_dst_port < mirror->n_select_dst_port; n_dst_port++) {
                     dst_port = mirror->select_dst_port[n_dst_port];
                     if (strcmp(dst_port->name, src_port->name) == 0) {
                        both = true;
                        both_array[n_dst_port] = true;
                        break;
                     }
                  }
                  if (both) {
                     vty_out(vty, " Source: interface %s both%s", src_port->name, VTY_NEWLINE);
                  } else {
                     vty_out(vty, " Source: interface %s rx%s", src_port->name, VTY_NEWLINE);
                  }
               }
            }

            /* mirror transmit source ports */
            if (mirror->n_select_dst_port == 0) {
               vty_out(vty, " Source: interface tx none%s", VTY_NEWLINE);

            } else {

               for (n_dst_port=0; n_dst_port < mirror->n_select_dst_port; n_dst_port++ ) {

                  if (!both_array[n_dst_port]) {
                     dst_port = mirror->select_dst_port[n_dst_port];
                     vty_out(vty, " Source: interface %s tx%s", dst_port->name, VTY_NEWLINE);
                  }
               }

               if (both_array) {
                  free (both_array);
                  both_array = NULL;
               }
            }

            vty_out(vty, " Destination: interface %s%s", (mirror->output_port ?
                                                    mirror->output_port->name :
                                                          "none"), VTY_NEWLINE);

            datum = ovsrec_mirror_get_statistics(mirror, OVSDB_TYPE_STRING,
                                                        OVSDB_TYPE_INTEGER);
            if (NULL == datum) continue;

            atom.string = mirror_statistics[0];
            index = ovsdb_datum_find_key(datum, &atom, OVSDB_TYPE_STRING);
            vty_out(vty, " Output Packets: %ld%s",
                       ((index == UINT_MAX)? 0 : datum->values[index].integer),
                                                                  VTY_NEWLINE);
            atom.string = mirror_statistics[1];
            index = ovsdb_datum_find_key(datum, &atom, OVSDB_TYPE_STRING);
            vty_out(vty, " Output Bytes: %ld%s",
                       ((index == UINT_MAX)? 0 : datum->values[index].integer),
                                                                  VTY_NEWLINE);
            break;
         }

      } else {

         found++;
         /* show all mode, print mirror summary */
         if (found == 1) {

            /* all-mirror header */
            vty_out(vty, "%s", VTY_NEWLINE);
            vty_out(vty, "name                                              "
                         "              status%s", VTY_NEWLINE);
            vty_out(vty, "--------------------------------------------------"
                         "------------- --------------%s", VTY_NEWLINE);
         }

         mstate = smap_get (&mirror->mirror_status, "operation_state");
         vty_out(vty, "%-63s %-14s%s", mirror->name,
                      (mstate ? mstate : "shutdown"), VTY_NEWLINE);

      }

   }

   if (!found) {

      if (NULL == mirror_arg) {
            vty_out(vty, "No mirror sessions exist%s", VTY_NEWLINE);
      } else {
            vty_out(vty, "Invalid mirror session '%s'%s", mirror_arg, VTY_NEWLINE);
      }
      return CMD_OVSDB_FAILURE;
   }

   return CMD_SUCCESS;
}


bool
are_all_chars_valid(const char* str)
{

   int x = 0;
   bool valid = true;

   for (x=0; x<strlen(str); x++)
   {
      if (!(((str[x] >= 0x30) && (str[x] <= 0x39)) ||   // numbers
            ((str[x] >= 0x41) && (str[x] <= 0x5a)) ||   // uppercase chars
            ((str[x] >= 0x61) && (str[x] <= 0x7a)) ||   // lowercase chars
             (str[x] != 0x5f) ||                        // underscore
             (str[x] != 0x2d) ||                        // dash
             (str[x] != 0x23))) {                       // period
         valid = false;
         break;
      }
   }

   return valid;

}


/* basic mirror session name validation */
bool
is_mirror_session_name_valid(const char* session_name)
{

   /* is session name too short? */
   if (strlen(session_name) == 0) {
      vty_out (vty, "Mirror session name required%s", VTY_NEWLINE);
      return false;
   }

   /* is session name too long? */
   if (strlen(session_name) > MAX_MIRROR_SESSION_NAME_LEN) {
      vty_out (vty, "Mirror session name too long (max %d)%s", MAX_MIRROR_SESSION_NAME_LEN, VTY_NEWLINE);
      return false;
   }

   /* is session name comprised of all legal chars */
   if (!are_all_chars_valid(session_name)) {
      vty_out (vty, "Invalid characters used in mirror session name%s", VTY_NEWLINE);
      return false;
   }

   return true;
}


/* add/delete a mirror session uuid in the bridge's 'mirrors' column.
 * assumes the default bridge 'bridge_normal'
 */
bool
update_bridge_mirrors (struct ovsrec_mirror *mirror_row, bool delete)
{

   const struct ovsrec_bridge *bridge_row = NULL;
   const struct ovsrec_bridge *default_bridge_row = NULL;
   struct ovsrec_mirror** mirrors = NULL;
   int i, j, n_mirrors = 0;

   default_bridge_row = ovsrec_bridge_first(idl);
   if (default_bridge_row != NULL)
   {
      OVSREC_BRIDGE_FOR_EACH(bridge_row, idl)
      {
         if (strcmp(bridge_row->name, DEFAULT_BRIDGE_NAME) == 0)
         {
            default_bridge_row = (struct ovsrec_bridge*)bridge_row;
            break;
         }
      }

      if (default_bridge_row == NULL)
      {
         VLOG_DBG("Couldn't find default bridge. Function=%s, Line=%d", __func__, __LINE__);
         vty_out(vty, "Failed to update the bridge%s", VTY_NEWLINE);
         return false;
      }
   }

   /* more or less? */
   if (delete) {
      n_mirrors = default_bridge_row->n_mirrors - 1;
   } else {
      n_mirrors = default_bridge_row->n_mirrors + 1;
   }

   /* build new bridge row mirrors map */
   mirrors = xmalloc(sizeof(*default_bridge_row->mirrors) * n_mirrors);

   /* copy over all existing mirrors.. */
   for (i=0,j=0; i < default_bridge_row->n_mirrors; i++,j++)
   {
      /* ..unless it's the one we're deleting */
      if (delete && default_bridge_row->mirrors[i] == mirror_row) {
         j--;
         continue;
      }

      mirrors[j] = default_bridge_row->mirrors[i];
   }

   if (!delete) {
      /* new mirror case */
      mirrors[default_bridge_row->n_mirrors] = CONST_CAST(struct ovsrec_mirror*,mirror_row);
   }
   ovsrec_bridge_set_mirrors(default_bridge_row, mirrors, n_mirrors);
   free (mirrors);
   return true;

}


/* from a user specified string/name, attempts to locate a mirror session with
 * that name in the Mirror table
 */
const struct ovsrec_mirror*
retrieve_mirror_row(const char* name)
{

   const struct ovsrec_mirror* row = NULL;
   OVSREC_MIRROR_FOR_EACH (row, idl)
   {
      /* looking for specified mirror */
      if (strncmp(name, row->name, MAX_MIRROR_SESSION_NAME_LEN) == 0) {
         return row;
      }
   }

   return NULL;
}


/* creates/deletes a row in the mirror table, and makes a call to update the
 * bridge row 'mirrors' column accordingly.
 */
bool
create_mirror_row(const char *name, struct ovsdb_idl_txn *txn)
{

   struct ovsrec_mirror *row = NULL;

   row = ovsrec_mirror_insert(txn);
   if (NULL != row)
   {
      ovsrec_mirror_set_name(row, name);
      if (!update_bridge_mirrors(row, false)) {
         // bridge update failed, try to unwind
         ovsrec_mirror_delete(row);
         return false;
      }

   }
   return true;
}


/* checks if a single interface/port is an active mirror destination */
bool
is_port_an_active_dest(const struct ovsrec_port* port)
{

   const struct ovsrec_mirror *mirror = NULL;

   OVSREC_MIRROR_FOR_EACH (mirror, idl) {

      /* ignore inactive mirrors */
      if ((mirror->active == NULL) || (*mirror->active == false)) {
         continue;
      }

      if (strcmp (port->name, mirror->output_port->name) == 0) {
         return true;
      }

   }
   return false;
}

/* function indicates whether port is already a member of the current mirror's
 * source rx interface set (select_src_port)
 * intended use is for avoiding unnecessary database updates to mirror on
 * source interface add or delete operations.
 */
bool
is_port_in_src_set(const struct ovsrec_mirror *mirror,
                       const struct ovsrec_port* port)
{
   int i = 0;
   if (mirror->n_select_src_port == 0) {
      return false;
   }

   for (i=0; i < mirror->n_select_src_port; i++)
   {
      if (mirror->select_src_port[i] == port) {
         return true;
      }
   }
   return false;
}


/* function indicates whether port is already a member of the current mirror's
 * source tx interface set (select_dst_port)
 * intended use is for avoiding unnecessary database updates to mirror on
 * source interface add or delete operations.
 */
bool
is_port_in_dst_set(const struct ovsrec_mirror *mirror,
                       const struct ovsrec_port* port)
{
   int i = 0;
   if (mirror->n_select_dst_port == 0) {
      return false;
   }

   for (i=0; i < mirror->n_select_dst_port; i++)
   {
      if (mirror->select_dst_port[i] == port) {
         return true;
      }
   }
   return false;
}



/* check whether an interface is a 'port'/has an entry in the port table.
 */
const struct ovsrec_port*
is_iface_a_port (const char* iface)
{
   const struct ovsrec_port *port_row = NULL;
   OVSREC_PORT_FOR_EACH(port_row, idl)
   {
      if (strcmp(port_row->name, iface) == 0) {

         return port_row;
      }
   }
   return NULL;
}

/* utility to determine if a mirror is active */
bool
is_mirror_active(const struct ovsrec_mirror *mirror)
{

   if ((mirror->active != NULL) && (*mirror->active == true)) {
      return true;
   }
   return false;

}
/* add an interface as a source of tx traffic to the current mirror session.
 * interface should already have been verified as having a port table entry,
 * and that that port does not already exist in the mirror's select_dst_port
 * set.
 */
int
update_dst_port (const struct ovsrec_mirror *mirror,
                     const struct ovsrec_port *port,
                                        bool delete)
{
   int i,j = 0;
   size_t n_ports = 0;
   struct ovsrec_port** ports = NULL;

   if (delete) {
      n_ports = mirror->n_select_dst_port - 1;
   } else {
      n_ports = mirror->n_select_dst_port + 1;
   }

   ports = xmalloc(sizeof(*mirror->select_dst_port) * n_ports);

   /* copy over all existing ports.. */
   for (i=0,j=0; i < mirror->n_select_dst_port; i++,j++)
   {
      /* ..unless it's the one we're deleting */
      if (delete && mirror->select_dst_port[i] == port) {
         j--;
         continue;
      }

      ports[j] = mirror->select_dst_port[i];
   }

   if (!delete) {
      /* new port */
      ports[mirror->n_select_dst_port] = CONST_CAST(struct ovsrec_port*, port);
   }

   ovsrec_mirror_set_select_dst_port(mirror, ports, n_ports);

   free (ports);
   return CMD_SUCCESS;
}


/* add an interface as a source of rx traffic to the current mirror session.
 * interface should already have been verified as having a port table entry,
 * and that that port does not already exist in the mirror's select_src_port
 * set.
 */
int
update_src_port (const struct ovsrec_mirror *mirror,
                     const struct ovsrec_port *port,
                                        bool delete)
{
   int i,j = 0;
   size_t n_ports = 0;
   struct ovsrec_port** ports = NULL;

   if (delete) {
      n_ports = mirror->n_select_src_port - 1;
   } else {
      n_ports = mirror->n_select_src_port + 1;
   }

   ports = xmalloc(sizeof(*mirror->select_src_port) * n_ports);

   /* copy over all existing ports.. */
   for (i=0,j=0; i < mirror->n_select_src_port; i++,j++)
   {
	  /* ..unless it's the one we're deleting */
      if (delete && mirror->select_src_port[i] == port) {
         j--;
         continue;
      }

      ports[j] = mirror->select_src_port[i];
   }

   if (!delete) {
      /* new port */
      ports[mirror->n_select_src_port] = CONST_CAST(struct ovsrec_port*, port);
   }

   ovsrec_mirror_set_select_src_port(mirror, ports, n_ports);

   free (ports);
   return CMD_SUCCESS;
}


/* the main interface to creating or deleting a mirror session.
 * if the mirror exists this is retrieved/deleted, if not call is made to
 * create it,
 */
int
mirror_session_exec (const char* name, bool delete)
{

   const struct ovsrec_mirror *row = NULL;
   struct ovsdb_idl_txn *txn = NULL;
   enum ovsdb_idl_txn_status txn_status;

   if (!is_mirror_session_name_valid(name)) {
      vty_out (vty, "Invalid session name%s", VTY_NEWLINE);
      return CMD_ERR_NO_MATCH;
   }

   txn = cli_do_config_start();
   if (!txn) {
       VLOG_ERR("Unable to acquire transaction");
      return CMD_OVSDB_FAILURE;
   }

   row = retrieve_mirror_row(name);
   if (NULL == row) {

      if (delete) {
         vty_out (vty, "Mirror session doesn't exist%s", VTY_NEWLINE);
         cli_do_config_abort(txn);
         return CMD_ERR_NO_MATCH;
      }

      if (!create_mirror_row(name, txn)) {
         vty_out (vty, "Failed to create mirror session%s", VTY_NEWLINE);
         cli_do_config_abort(txn);
         return CMD_OVSDB_FAILURE;
      }

   } else {
      if (delete) {
         update_bridge_mirrors((struct ovsrec_mirror*)row, true);
         ovsrec_mirror_delete(row);
      }
   }

   txn_status = cli_do_config_finish(txn);

   if (txn_status != TXN_SUCCESS && txn_status != TXN_UNCHANGED) {
      VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
      return CMD_OVSDB_FAILURE;
   }

   if (delete) {
      vty->node = CONFIG_NODE;
      vty->index = NULL;
   } else {
      strncpy (g_mirror_name, name, sizeof(g_mirror_name));
      vty->node = MIRROR_NODE;
      vty->index = (void*)g_mirror_name;
   }
   return CMD_SUCCESS;
}


/* A mirror can replicate a source interface's ingress traffic only, egress
 * traffic only, or both directions, for that interface.
 * In the ovsdb schema for a given Mirror table row (session), source ingress/rx
 * mirroring is recorded in the column 'select_src_port' source egress/tx is
 * recorded in 'select_dst_port' (not to be confused with the mirror's
 * destination port, which is recorded in the column 'output_port') and a
 * direction of 'both' has entries in both columns.
 * Where there can be only one mirror destination port (output_port), there
 * can be multiple source ports specified in any combination of direction.
 * Source ports include LAGs.
 */
int
source_iface_exec(const char* iface_name, const char* direction, bool delete)
{

   const struct ovsrec_mirror *mirror = NULL;
   const struct ovsrec_port *port_row = NULL;
   struct ovsdb_idl_txn *txn = NULL;
   enum ovsdb_idl_txn_status txn_status;
   int rc = CMD_SUCCESS;

   port_row = is_iface_a_port(iface_name);
   if (NULL == port_row) {
      vty_out (vty, "Invalid interface %s%s", iface_name, VTY_NEWLINE);
      return CMD_ERR_NO_MATCH;
   }

   if (vty->index == NULL) {
      VLOG_ERR("Unable to locate mirror session");
      return CMD_ERR_NO_MATCH;
   }

   txn = cli_do_config_start();
   if (!txn) {
      VLOG_ERR("Unable to acquire transaction");
      return CMD_OVSDB_FAILURE;
   }

   mirror = retrieve_mirror_row((const char*)vty->index);
   if (mirror == NULL) {
      vty_out (vty, "Mirror session %s doesn't exist%s",
                                (const char*)vty->index,
                                            VTY_NEWLINE);
      return CMD_ERR_NO_MATCH;
   }


   if (delete) {

      if ((rc == CMD_SUCCESS)                                           &&
          /* remove interface src/rx on null (both) or 'tx' */
          ((direction == NULL) || (strcmp(direction, SRC_DIR_RX) == 0)) &&
           (is_port_in_src_set(mirror, port_row))) {

         rc = update_src_port (mirror, port_row, true);
      }

      if ((rc == CMD_SUCCESS)                                           &&
          /* remove interface dst/tx on null (both) or 'tx' */
          ((direction == NULL) || (strcmp(direction, SRC_DIR_TX) == 0)) &&
           (is_port_in_dst_set(mirror, port_row))) {

         rc = update_dst_port (mirror, port_row, true);
      }

   } else {

      /* Source port add can be for inbound/tx traffic (src), outbound/tx (dst)
       * or both.
       * On port add, an unactivated mirror's configuration is not validated
       * with the exception that a port cannot be both source & destination.
       * When active, add operations are subject to stricter validation
       * according to the mirror port membership rules.
       */

      /* a port can't be both source & dest */
      if ((mirror->output_port) &&
          (strcmp (port_row->name, mirror->output_port->name) == 0)) {
         vty_out (vty, "Cannot add source, interface %s is already the destination interface%s",
                                                                 port_row->name,
                                                                   VTY_NEWLINE);
         rc = true;
      }

      /* add operation for tx/both */
      if ((strcmp(direction, SRC_DIR_TX) == 0) ||
          (strcmp(direction, SRC_DIR_BOTH) == 0)) {

         /* first, if tx/dst only, and this port exist in rx/src, remove it
          * (implicit replace/remove)
          */
         if ((rc == CMD_SUCCESS) && (strcmp(direction, SRC_DIR_TX) == 0) &&
                                    (is_port_in_src_set(mirror, port_row))) {

               rc = update_src_port (mirror, port_row, true);
         }

         /* add op, if necessary */
         if ((rc == CMD_SUCCESS) && (!is_port_in_dst_set(mirror, port_row))) {

            /* if this mirror is active, see if this new source rx port is a
             * dest in an active mirror (incl this mirror).  if so, can't add */
            if (is_mirror_active(mirror)) {

               if (is_port_an_active_dest(port_row)) {
                  vty_out (vty, "Cannot add, interface %s is currently an active mirror destination%s",
                                                                 port_row->name,
                                                                   VTY_NEWLINE);
                  /* TODO: proper error codes? */
                  rc = true;
               }
            }

            if (rc == CMD_SUCCESS)  {
               /* legal add */
               rc = update_dst_port (mirror, port_row, false);
            }
         }

      }

      /* add operation for rx/both */
      if ((strcmp(direction, SRC_DIR_RX) == 0) ||
          (strcmp(direction, SRC_DIR_BOTH) == 0)) {

         /* first, if rx/src only, and this port exist in tx/dst, remove it
          * (implicit replace/remove)
          */
         if ((rc == CMD_SUCCESS) && (strcmp(direction, SRC_DIR_RX) == 0) &&
                                    (is_port_in_dst_set(mirror, port_row))) {

            rc = update_dst_port (mirror, port_row, true);
         }

         if ((rc == CMD_SUCCESS) && (!is_port_in_src_set(mirror, port_row))) {


            /* if this mirror is active, see if this new source tx port is a
             * dest in an active mirror (incl this mirror).  if so, can't add */
            if (is_mirror_active(mirror)) {

               if (is_port_an_active_dest(port_row)) {
                  /* TODO: error codes */
                  vty_out (vty, "Cannot add, interface %s is currently an active mirror destination%s",
                                                                 port_row->name,
                                                                   VTY_NEWLINE);
                  rc = true;
               }
            }

            if (rc == CMD_SUCCESS)  {
               /* legal add */
               rc = update_src_port (mirror, port_row, false);
            }
         }
      }
   }

   if (rc != CMD_SUCCESS) {
      cli_do_config_abort(txn);
      return CMD_OVSDB_FAILURE;
   }

   txn_status = cli_do_config_finish(txn);

   if (txn_status != TXN_SUCCESS && txn_status != TXN_UNCHANGED) {
      VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
      return CMD_OVSDB_FAILURE;
   }

   return CMD_SUCCESS;

}

/**
 * Set, or remove the destination (output) interface (port) for the mirror
 * session.
 *
 * @param iface_name    port name
 * @param delete        boolean: true=delete, false=add
 *
 * @return              CMD_SUCCESS on success
 */
int
output_iface_exec(const char* iface_name, bool delete)
{

   const struct ovsrec_mirror *mirror = NULL;
   const struct ovsrec_port *port_row = NULL;
   struct ovsdb_idl_txn *txn = NULL;
   enum ovsdb_idl_txn_status txn_status;


   // a null interface is valid for delete case
   if ((iface_name == NULL) && !delete) {
      return CMD_ERR_NO_MATCH;
   }

   if (vty->index == NULL) {
      VLOG_ERR("Unable to locate mirror session");
      return CMD_ERR_NO_MATCH;
   }

   txn = cli_do_config_start();
   if (!txn) {
        VLOG_ERR("Unable to acquire transaction");
        return CMD_OVSDB_FAILURE;
   }

   mirror = retrieve_mirror_row((const char*)vty->index);
   if (mirror == NULL) {
      vty_out (vty, "Mirror session %s doesn't exist%s",
                                (const char*)vty->index,
                                            VTY_NEWLINE);
      return CMD_ERR_NO_MATCH;
   }

   if (delete) {

      /* if active mirror, no mirroring w/out destination/output. shutdown */
      if ((mirror->active != NULL) && (*mirror->active == true)) {

         bool active = 0;
         ovsrec_mirror_set_active (mirror, &active, 1);
      }

      ovsrec_mirror_set_output_port(mirror, NULL);

   } else {

      port_row = is_iface_a_port(iface_name);
      if (port_row == NULL) {

         vty_out (vty, "Invalid interface %s%s", iface_name, VTY_NEWLINE);
         cli_do_config_abort(txn);
         return CMD_ERR_NO_MATCH;
      }

      if (is_port_in_src_set(mirror, port_row) ||
          is_port_in_dst_set(mirror, port_row)) {
         vty_out (vty, "Cannot add destination, interface %s is already a source%s",
                                                                 port_row->name,
                                                                   VTY_NEWLINE);
         cli_do_config_abort(txn);
         return CMD_ERR_NO_MATCH;
      }

      /* could be a first time add/inactive mirror update, or active change.
       * up to the bridge to respond to an active change.
       */
      ovsrec_mirror_set_output_port(mirror, port_row);
   }

   txn_status = cli_do_config_finish(txn);

   if (txn_status != TXN_SUCCESS && txn_status != TXN_UNCHANGED) {
      VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
      return CMD_OVSDB_FAILURE;
   }

   return CMD_SUCCESS;
}


/* activation rule: a mirror at minimum must have a destination interface
 * and at least one source interface configured.
 */
bool
is_mirror_config_adequate(const struct ovsrec_mirror* mirror)
{

   if (!mirror->output_port) {
      vty_out (vty, "No mirror destination interface configured%s", VTY_NEWLINE);
      return false;
   }

   if ((mirror->n_select_src_port == 0) &&
       (mirror->n_select_dst_port == 0)) {
      vty_out (vty, "No mirror source interface(s) configured%s", VTY_NEWLINE);
      return false;
   }

   return true;
}


/* activation rule: a source interface (tx or rx) must not be a destination
 * interface in any active mirror
 * compares all configured source interfaces, tx & rx against all active
 * destinations
 */
bool
is_a_src_iface_an_active_dest(const struct ovsrec_mirror* this_mirror)
{

   const struct ovsrec_mirror *mirror = NULL;
   const struct ovsrec_port *src_port = NULL;
   const struct ovsrec_port *dst_port = NULL;
   int n_dst_port, n_src_port = 0;

   OVSREC_MIRROR_FOR_EACH (mirror, idl) {

      /* ignore ourself */
      if (strcmp (this_mirror->name, mirror->name) == 0) {
         continue;
      }

      /* ignore inactive mirrors */
      if ((mirror->active == NULL) || (*mirror->active == false)) {
         continue;
      }

      /* this mirror source rx port check against other dest */
      if (this_mirror->n_select_src_port > 0) {

         for (n_src_port=0; n_src_port < this_mirror->n_select_src_port; n_src_port++) {

            src_port = this_mirror->select_src_port[n_src_port];

            if (strcmp (src_port->name, mirror->output_port->name) == 0) {
               vty_out (vty, "Interface (%s) already in use as destination in active session %s%s",
                                                                src_port->name,
                                                      mirror->name,VTY_NEWLINE);
               return true;
            }
         }
      }

      /* this mirror source tx port check against other dest */
      if (this_mirror->n_select_dst_port > 0) {

         for (n_dst_port=0; n_dst_port < this_mirror->n_select_dst_port; n_dst_port++) {

            dst_port = this_mirror->select_dst_port[n_dst_port];

            if (strcmp (dst_port->name, mirror->output_port->name) == 0) {
               vty_out (vty, "Interface (%s) already in use as destination in active session %s%s",
                                                                src_port->name,
                                                      mirror->name,VTY_NEWLINE);
               return true;
            }
         }
      }
   }

   return false;
}


/* activation rule: a mirrors destination interface must not be a source or
 * destination in any other active mirror
 */
bool
is_dest_iface_in_active_use(const struct ovsrec_mirror* this_mirror)
{

   const struct ovsrec_mirror *mirror = NULL;
   const struct ovsrec_port *src_port = NULL;
   const struct ovsrec_port *dst_port = NULL;
   int n_dst_port, n_src_port = 0;

   OVSREC_MIRROR_FOR_EACH (mirror, idl) {

      /* ignore ourself */
      if (strcmp (this_mirror->name, mirror->name) == 0) {
         continue;
      }

      /* ignore inactive mirrors */
      if ((mirror->active == NULL) || (*mirror->active == false)) {
         continue;
      }

      /* other mirror dest/output port check againt this dest */
      if (strcmp (this_mirror->output_port->name,
                       mirror->output_port->name) == 0) {
         vty_out (vty, "Interface (%s) already in use as destination in active session %s%s",
                                                this_mirror->output_port->name,
                                                      mirror->name,VTY_NEWLINE);
         return true;
      }

      /* other mirror source rx port check */
      if (mirror->n_select_src_port > 0) {

         for (n_src_port=0; n_src_port < mirror->n_select_src_port; n_src_port++) {

            src_port = mirror->select_src_port[n_src_port];

            if (strcmp (this_mirror->output_port->name,
                                  src_port->name) == 0) {
               vty_out (vty, "Interface (%s) already in use as source in active session %s%s",
                                                this_mirror->output_port->name,
                                                      mirror->name,VTY_NEWLINE);
               return true;
            }
         }
      }

      /* other mirror source tx port check */
      if (mirror->n_select_dst_port > 0) {

         for (n_dst_port=0; n_dst_port < mirror->n_select_dst_port; n_dst_port++) {

            dst_port = mirror->select_dst_port[n_dst_port];

            if (strcmp (this_mirror->output_port->name,
                                  dst_port->name) == 0) {
               vty_out (vty, "Interface (%s) already in use as source in active session %s%s",
                                                this_mirror->output_port->name,
                                                      mirror->name,VTY_NEWLINE);
               return true;
            }
         }
      }
   }

   return false;
}


/* this function enforces the rules on whether a mirror session, when
 * activated is acceptably configured, that it's configured ports are not
 * already in use in another active mirror and so on.
 * the rules are described inline.
 */
bool
can_mirror_be_activated(const struct ovsrec_mirror* mirror)
{
   /* a mirror must have, at minimum, a single source interface, and only one
    * destination interface
    */
   if (!is_mirror_config_adequate(mirror)) {
      return false;
   }

   /* a mirror's destination interface must not be a source or destination in
    * any other active mirror session
    */
   if (is_dest_iface_in_active_use(mirror)) {
      return false;
   }

   /* a mirror's source interfaces must not be a destination in any other active
    * mirror session
    */
   if (is_a_src_iface_an_active_dest(mirror)) {
      return false;
   }

   /* a mirror's destination interface must not be participating in any form
    * of spanning tree protocol
    */
   // TBD

   /* a mirror's destination interface must not have an ip address configured
    *
    */
   // TBD

   /* a mirror's destination interface must not have routing enabled
    *
    */
   // TBD

   return true;
}


int
mirror_activate (bool activate)
{
   struct ovsdb_idl_txn *txn = NULL;
   enum ovsdb_idl_txn_status txn_status;
   const struct ovsrec_mirror *mirror = NULL;

   if (NULL == vty->index) {
      VLOG_ERR("Unable to locate mirror session");
      return CMD_ERR_NO_MATCH;
   }

   txn = cli_do_config_start();
   if (!txn) {
      VLOG_ERR("Unable to acquire transaction");
      return CMD_OVSDB_FAILURE;
   }

   mirror = retrieve_mirror_row((const char*)vty->index);
   if (mirror == NULL) {
      vty_out (vty, "Mirror session %s doesn't exist%s",
                                (const char*)vty->index,
                                            VTY_NEWLINE);
      return CMD_ERR_NO_MATCH;
   }

   if (activate) {

      if (can_mirror_be_activated(mirror)) {

         ovsrec_mirror_set_active (mirror, &activate, 1);

      } else {

         /* validation code will already have indicated the issue to terminal */
         cli_do_config_abort(txn);
         return CMD_ERR_INCOMPLETE;
      }
   } else {

      /* deactivate/shutdown */
      ovsrec_mirror_set_active (mirror, &activate, 1);
   }

   txn_status = cli_do_config_finish(txn);

   if (txn_status != TXN_SUCCESS && txn_status != TXN_UNCHANGED) {
      VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
      return CMD_OVSDB_FAILURE;
   }

   return CMD_SUCCESS;
}


DEFUN(cli_no_mirror_session,
      cli_no_mirror_session_cmd,
      "no mirror session NAME",
      NO_STR
      MIRROR_STR
      MIRROR_SESSION_STR
      MIRROR_SESSION_NAME_STR)
{

   if (argc != 1) {
      vty_out (vty, "Session name required%s", VTY_NEWLINE);
      return 1;
   }
   return mirror_session_exec ((const char*)argv[0], true);
}


DEFUN(cli_mirror_session,
      cli_mirror_session_cmd,
      "mirror session NAME",
      MIRROR_STR
      MIRROR_SESSION_STR
      MIRROR_SESSION_NAME_STR)
{

   if (argc != 1) {
      vty_out (vty, "Session name required%s", VTY_NEWLINE);
      return 1;
   }
   return mirror_session_exec ((const char*)argv[0], false);
}


DEFUN (cli_show_mirrors,
       cli_show_mirrors_cmd,
      "show mirror",
      SHOW_STR
      "Show all configured mirrors\n")
{

   return cli_show_mirror_exec(NULL);

}

DEFUN (cli_show_a_mirror,
       cli_show_a_mirror_cmd,
      "show mirror MIRROR",
      SHOW_STR
      "Port mirror"
      "Name of existing mirror session\n")
{

   if (argc != 1) {
      vty_out (vty, "Mirror name required%s", VTY_NEWLINE);
      return 1;
   }

   return cli_show_mirror_exec(argv[0]);

}


DEFUN (cli_mirror_source_iface_dir,
       cli_mirror_source_iface_dir_cmd,
       "source interface INTERFACE (both|rx|tx)",
       SRC_STR
       IFACE_STR
       IFACE_NAME_STR
       SRC_DIR_BOTH
       SRC_DIR_RX
       SRC_DIR_TX)
{
   if ((NULL == argv[0]) || (NULL == argv[1])) {
       vty_out (vty, "Interface name & traffic direction required%s", VTY_NEWLINE);
       return 1;
   }

   return source_iface_exec((const char*)argv[0], (const char*)argv[1],  false);

}

DEFUN (cli_mirror_no_source_iface,
       cli_mirror_no_source_iface_cmd,
       "no source interface INTERFACE",
       SRC_STR
       IFACE_STR
       IFACE_NAME_STR)
{
   if (NULL == argv[0]) {
      vty_out (vty, "Interface name required%s", VTY_NEWLINE);
      return 1;
   }

   return source_iface_exec((const char*)argv[0], NULL, true);

}

DEFUN (cli_mirror_no_source_iface_dir,
       cli_mirror_no_source_iface_dir_cmd,
       "no source interface INTERFACE (rx|tx)",
       SRC_STR
       IFACE_STR
       IFACE_NAME_STR
       SRC_DIR_RX
       SRC_DIR_TX)
{
   if (NULL == argv[0]) {
      vty_out (vty, "Interface name required%s", VTY_NEWLINE);
      return 1;
   }

   return source_iface_exec((const char*)argv[0], (const char*)argv[1], true);

}

DEFUN (cli_mirror_output_iface,
       cli_mirror_output_iface_cmd,
       "destination interface INTERFACE",
       DST_STR
       IFACE_STR
       IFACE_NAME_STR)
{
   if (NULL == argv[0]) {
      vty_out (vty, "Interface name required%s", VTY_NEWLINE);
      return 1;
   }

   return output_iface_exec((const char*)argv[0], false);

}


DEFUN (cli_mirror_no_output_iface,
       cli_mirror_no_output_iface_cmd,
       "no destination interface",
       NO_STR
       DST_STR
       IFACE_STR)
{
   return output_iface_exec(NULL, true);

}



DEFUN (cli_mirror_no_shutdown,
       cli_mirror_no_shutdown_cmd,
       "no shutdown",
       SHUT_STR)
{
   return mirror_activate (true);

}

DEFUN (cli_mirror_shutdown,
       cli_mirror_shutdown_cmd,
	   "shutdown",
	   SHUT_STR)
{
   return mirror_activate (false);

}


/**
 * Prompt string when in mirror context
 */
static struct cmd_node mirror_node = {
    MIRROR_NODE,
    "%s(config-mirror)# "
};


void
mirror_pre_init(void)
{
   install_node (&mirror_node, NULL);
   vtysh_install_default(MIRROR_NODE);

   ovsdb_idl_add_table(idl, &ovsrec_table_bridge);
   ovsdb_idl_add_column(idl, &ovsrec_bridge_col_mirrors);

   ovsdb_idl_add_table(idl, &ovsrec_table_mirror);
   ovsdb_idl_add_column(idl, &ovsrec_mirror_col_output_port);
   ovsdb_idl_add_column(idl, &ovsrec_mirror_col_statistics);
   ovsdb_idl_add_column(idl, &ovsrec_mirror_col_name);
   ovsdb_idl_add_column(idl, &ovsrec_mirror_col_active);
   ovsdb_idl_add_column(idl, &ovsrec_mirror_col_mirror_status);
   ovsdb_idl_add_column(idl, &ovsrec_mirror_col_select_src_port);
   ovsdb_idl_add_column(idl, &ovsrec_mirror_col_select_dst_port);
   ovsdb_idl_add_column(idl, &ovsrec_mirror_col_output_port);

}

void
mirror_vty_init(void)
{
    install_element (ENABLE_NODE, &cli_show_mirrors_cmd);
    install_element (ENABLE_NODE, &cli_show_a_mirror_cmd);

    install_element (CONFIG_NODE, &cli_mirror_session_cmd);
    install_element (CONFIG_NODE, &cli_no_mirror_session_cmd);

    install_element(MIRROR_NODE, &config_exit_cmd);
    install_element(MIRROR_NODE, &config_quit_cmd);
    install_element(MIRROR_NODE, &config_end_cmd);

    install_element(MIRROR_NODE, &cli_mirror_output_iface_cmd);
    install_element(MIRROR_NODE, &cli_mirror_no_output_iface_cmd);

    install_element(MIRROR_NODE, &cli_mirror_source_iface_dir_cmd);
    install_element(MIRROR_NODE, &cli_mirror_no_source_iface_cmd);
    install_element(MIRROR_NODE, &cli_mirror_no_source_iface_dir_cmd);

    install_element(MIRROR_NODE, &cli_mirror_shutdown_cmd);
    install_element(MIRROR_NODE, &cli_mirror_no_shutdown_cmd);
}
