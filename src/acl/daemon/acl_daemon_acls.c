/*
 * (c) Copyright 2016 Hewlett Packard Enterprise Development LP
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
/************************************************************************//**
 * @ingroup acl_daemon_acls
 *
 * @file
 * Source for ACL table related processing required by ACL feature in
 * classifier daemon.
 *
 ***************************************************************************/
#include <openvswitch/vlog.h>
#include <assert.h>
#include <vswitch-idl.h>
#include <acl_daemon.h>

VLOG_DEFINE_THIS_MODULE(acl_daemon_acls);

/**
 * Process ACL table changes to determine if in_progress_aces
 * needs to be updated or not
 */
int
acl_reconfigure(struct ovsdb_idl *idl, unsigned int idl_seqno)
{
    int rc = 0;
    const struct ovsrec_acl *acl_row = NULL;

    VLOG_DBG("acl_reconfigure...\n");

    /* get first port row from IDL cache */
    acl_row = ovsrec_acl_first(idl);

    OVSREC_ACL_FOR_EACH (acl_row, idl) {
        VLOG_DBG("ACL %s:  \n",acl_row->name);
    } /* for each acl ROW */

    VLOG_DBG("%s: number of updates back to db: %d",__FUNCTION__,rc);

    return rc;
} /* acl_reconfigure */


/** @} end of group acl_daemon_acls */
