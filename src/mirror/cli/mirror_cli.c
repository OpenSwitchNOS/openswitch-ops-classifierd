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


#define MAX_MIRROR_SESSION_NAME_LEN 64
#define MIRROR_STR           "mirror"
#define MIRROR_SESSION_STR   "mirror_session"
#define MIRROR_SESSION_NAME_STR "mirror_session_name"
#define DST_STR              "destination"
#define IFACE_STR            "interface"
#define IFACE_NAME_STR       "interface_name"
#define SRC_STR              "source"
#define SRC_DIR_TX           "tx"
#define SRC_DIR_RX           "rx"
#define SRC_DIR_BOTH         "both"
#define SHUT_STR             "shutdown"


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

      if (NULL != mirror_arg)
      {
         /* looking for specified mirror */
         if (0 == strncmp(mirror_arg, mirror->name,
                (MAX_MIRROR_SESSION_NAME_LEN-1))) {
            found++;

            /* print mirror detail */
            vty_out(vty, "%s", VTY_NEWLINE);
            vty_out(vty, " Mirror Session: %s%s", mirror->name, VTY_NEWLINE);

            mstate = smap_get (&mirror->mirror_status, "operation_state");
            vty_out(vty, " Status: %s%s", (mstate ? mstate : "shutdown"),
                                                            VTY_NEWLINE);

            /* an array to flag which select_dst_ports are found to be 'both'
             * so we don't have to loop both src & dst ports twice */
            if (mirror->n_select_dst_port > 0) {
               both_array = xcalloc(mirror->n_select_dst_port, sizeof *both_array);
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
                        both_array[n_dst_port] = 1;
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


bool
is_mirror_session_name_valid(const char* session_name)
{

   /* is session name too short? */
   if (strlen(session_name) == 0)
   {
      vty_out (vty, "Mirror session name required%s", VTY_NEWLINE);
      return false;
   }

   /* is session name too long? */
   if (strlen(session_name) > MAX_MIRROR_SESSION_NAME_LEN) {
      vty_out (vty, "Mirror session name too long (max %d)%s", MAX_MIRROR_SESSION_NAME_LEN, VTY_NEWLINE);
      return false;
   }

   /* is session name comprised of all legal chars */
   if (!are_all_chars_valid(session_name))
   {
      vty_out (vty, "Invalid characters used in mirror session name%s", VTY_NEWLINE);
      return false;
   }

   return true;
}


const struct ovsrec_mirror*
retrieve_mirror_row(const char* name)
{

   const struct ovsrec_mirror* row = NULL;
   OVSREC_MIRROR_FOR_EACH (row, idl)
   {
      /* looking for specified mirror */
      if (0 == strncmp(name, row->name, MAX_MIRROR_SESSION_NAME_LEN)) {
         return row;
      }
   }

   return NULL;
}


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
         vty_out(vty, "Failed to create the vlan%s", VTY_NEWLINE);
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

struct ovsrec_mirror *
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
         row = NULL;
      }

   }
   return row;
}


int
mirror_session_exec (const char* name, bool delete)
{

   const struct ovsrec_mirror *row = NULL;
   struct ovsdb_idl_txn *txn = NULL;
   enum ovsdb_idl_txn_status txn_status;

   txn = cli_do_config_start();
   if (!txn) {
       VLOG_ERR("Unable to acquire transaction");
      return CMD_OVSDB_FAILURE;
   }

   if (!is_mirror_session_name_valid(name)) {
      vty_out (vty, "Invalid session name%s", VTY_NEWLINE);
      cli_do_config_abort(txn);
      return CMD_ERR_NO_MATCH;
   }


   row = retrieve_mirror_row(name);
   if (NULL == row) {

      if (delete) {
         vty_out (vty, "Mirror session doesn't exist%s", VTY_NEWLINE);
         cli_do_config_abort(txn);
         return CMD_ERR_NO_MATCH;
      }

      row = create_mirror_row(name, txn);
      if (NULL == row) {

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
      //strncpy(g_mirror_name, name, sizeof(g_mirror_name));
      vty->node = MIRROR_NODE;
      vty->index = (void*)row;
   }
   return CMD_SUCCESS;
}


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


int
update_dst_port (const struct ovsrec_port *port, bool delete)
{
   int i,j = 0;
   size_t n_ports = 0;
   struct ovsrec_port** ports = NULL;
   const struct ovsrec_mirror *mirror = NULL;

   if (vty->index == NULL) {
       VLOG_ERR("Unable to locate mirror session");
	   return 1;
   }
   mirror = (const struct ovsrec_mirror*)vty->index;

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
   return true;
}


int
update_src_port (const struct ovsrec_port *port, bool delete)
{
   int i,j = 0;
   size_t n_ports = 0;
   struct ovsrec_port** ports = NULL;
   const struct ovsrec_mirror *mirror = NULL;

   if (vty->index == NULL) {
       VLOG_ERR("Unable to locate mirror session");
	   return 1;
   }
   mirror = (const struct ovsrec_mirror*)vty->index;

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
   return true;


}


bool
is_port_in_src_set(const struct ovsrec_port* port)
{
   int i =0;
   const struct ovsrec_mirror *mirror = NULL;

   if (vty->index == NULL) {
       VLOG_ERR("Unable to locate mirror session");
	   return 1;
   }
   mirror = (const struct ovsrec_mirror*)vty->index;

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


bool
is_port_in_dst_set(const struct ovsrec_port* port)
{
   int i =0;
   const struct ovsrec_mirror *mirror = NULL;

   if (vty->index == NULL) {
       VLOG_ERR("Unable to locate mirror session");
	   return 1;
   }
   mirror = (const struct ovsrec_mirror*)vty->index;

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

   const struct ovsrec_port *port_row = NULL;
   struct ovsdb_idl_txn *txn = NULL;
   enum ovsdb_idl_txn_status txn_status;

   txn = cli_do_config_start();
   if (!txn) {
      VLOG_ERR("Unable to acquire transaction");
      cli_do_config_abort(txn);
      return CMD_OVSDB_FAILURE;
   }

   port_row = is_iface_a_port(iface_name);
   if (NULL == port_row) {
      vty_out (vty, "Invalid interface %s%s", iface_name, VTY_NEWLINE);
      cli_do_config_abort(txn);
      return CMD_ERR_NO_MATCH;
   }

   if (delete) {

      if (is_port_in_src_set(port_row)) {
         update_src_port (port_row, true);
      }

      if (is_port_in_dst_set(port_row)) {
         update_dst_port (port_row, true);
      }

   } else {

      if ((0 == strcmp(direction, SRC_DIR_TX)) ||
          (0 == strcmp(direction, SRC_DIR_BOTH))) {

         if (!is_port_in_dst_set(port_row)) {
            update_dst_port (port_row, false);
         }
      }

      if ((0 == strcmp(direction, SRC_DIR_RX)) ||
          (0 == strcmp(direction, SRC_DIR_BOTH))) {

         if (!is_port_in_src_set(port_row)) {
            update_src_port (port_row, false);
         }
      }
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

   txn = cli_do_config_start();
   if (!txn) {
        VLOG_ERR("Unable to acquire transaction");
        return CMD_OVSDB_FAILURE;
   }

   // a null interface is valid for delete case
   if ((iface_name == NULL) && !delete) {
      cli_do_config_abort(txn);
	  return 1;
   }

   if (vty->index == NULL) {
      VLOG_ERR("Unable to locate mirror session");
      cli_do_config_abort(txn);
	  return 1;
   }

   mirror = (const struct ovsrec_mirror*)vty->index;

   if (delete) {
      ovsrec_mirror_set_output_port(mirror, NULL);

   } else {

      port_row = is_iface_a_port(iface_name);
      if (NULL != port_row) {
         ovsrec_mirror_set_output_port(mirror, port_row);
      } else {
	     vty_out (vty, "Invalid interface %s%s", iface_name, VTY_NEWLINE);
         cli_do_config_abort(txn);
         return CMD_ERR_NO_MATCH;
      }
   }

   txn_status = cli_do_config_finish(txn);

   if (txn_status != TXN_SUCCESS && txn_status != TXN_UNCHANGED) {
      VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
      return CMD_OVSDB_FAILURE;
   }

   return CMD_SUCCESS;
}

bool
is_mirror_config_ok(const struct ovsrec_mirror* mirror)
{
   mirror = NULL;
   return true;
}


int
mirror_activate (bool activate)
{
   struct ovsdb_idl_txn *txn = NULL;
   enum ovsdb_idl_txn_status txn_status;
   const struct ovsrec_mirror *mirror = NULL;

   txn = cli_do_config_start();
   if (!txn) {
        VLOG_ERR("Unable to acquire transaction");
        return CMD_OVSDB_FAILURE;
   }

   if (NULL == vty->index) {
       cli_do_config_abort(txn);
       VLOG_ERR("Unable to locate mirror session");
	   return 1;
   }

   mirror = (const struct ovsrec_mirror*)vty->index;

   if (activate) {

      if (is_mirror_config_ok(mirror)) {

         ovsrec_mirror_set_active (mirror, &activate, 1);
      } else {

	     vty_out (vty, "Mirror configuration error%s", VTY_NEWLINE);
         cli_do_config_abort(txn);
         return CMD_OVSDB_FAILURE;
      }
   } else {

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


DEFUN (cli_mirror_source_iface,
       cli_mirror_source_iface_cmd,
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
 * Prompt string when in access-list context
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

    install_element(MIRROR_NODE, &cli_mirror_source_iface_cmd);
    install_element(MIRROR_NODE, &cli_mirror_no_source_iface_cmd);

    install_element(MIRROR_NODE, &cli_mirror_shutdown_cmd);
    install_element(MIRROR_NODE, &cli_mirror_no_shutdown_cmd);
}
