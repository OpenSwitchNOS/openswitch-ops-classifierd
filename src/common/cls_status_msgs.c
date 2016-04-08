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
 * @ingroup  cls_status_msgs
 *
 * @file
 * Source for classifier status messages functions.
 *
 ***************************************************************************/

#include <openvswitch/vlog.h>
#include "ops-cls-asic-plugin.h"
#include "cls_status_table.h"
#include "cls_status_msgs.h"

/** Create logging module */
VLOG_DEFINE_THIS_MODULE(cls_status_msgs);

/** @ingroup cls_status_msgs
 * @{ */

/* This defines a common string that will be prefixed to the specific
 * error message. e.g.
 *  Failed to <operation> <feature> on <interface type> <interface#>
 *  <sequence_no_str>
 *   operation - apply, remove, replace, update, get, clear, clearll
 *   feature - acl, acl list, acl statistics
 *   interface type - port, vlan, etc
 *   interface# - interface number
 *   sequence_no_str - In case sequence number is valid, it will
 *                     display " at entry sequence number XX. "
 *                     otherwise, it will not display anything.
 */
#define CLS_STATUS_MSG_COMMON_ERR_PREFIX "Failed to %s %s on %s %d%s"

/* string to be displayed if sequence number is valid */
#define CLS_STATUS_MSG_SEQ_NUM_VALID    " at entry sequence number %d, "

/* string to be displayed if sequence number is NOT valid
 * e.g. statistics operations or general failures not specific
 * to an entry
 */
#define CLS_STATUS_MSG_SEQ_NUM_INVALID  "."

#define CLS_STATUS_MSG_SEQ_NUM_STR_LEN 64 /**< sequence number string length,
                                               strlen of
                                               CLS_STATUS_MSG_SEQ_VALID (27) +
                                               SEQ_NUM_TO_STR_MAX_LEN (11)
                                               rounded to power of 2
                                            */

#define STATUS_MSG_LEN 256       /**< status message string max length
                                      used only in debug function */

/* Classifier status messages */
const struct cls_status_entry cls_status_msgs[] = {
    {
	OPS_CLS_STATUS_SUCCESS,
	NULL
    },
    {
	OPS_CLS_STATUS_HW_INTERNAL_ERR,
	CLS_STATUS_MSG_COMMON_ERR_PREFIX "reason: internal error."
    },
    {
	OPS_CLS_STATUS_HW_MEMORY_ERR,
	CLS_STATUS_MSG_COMMON_ERR_PREFIX "reason: out of memory."
    },
    {
	OPS_CLS_STATUS_HW_UNIT_ERR,
	CLS_STATUS_MSG_COMMON_ERR_PREFIX "reason: invalid unit"
    },
    {
	OPS_CLS_STATUS_HW_PARAM_ERR,
	CLS_STATUS_MSG_COMMON_ERR_PREFIX "reason: invalid parameter"
    },
    {
	OPS_CLS_STATUS_HW_EMPTY_ERR,
	CLS_STATUS_MSG_COMMON_ERR_PREFIX "reason: empty table"
    },
    {
	OPS_CLS_STATUS_HW_FULL_ERR,
	CLS_STATUS_MSG_COMMON_ERR_PREFIX "reason: full table"
    },
    {
	OPS_CLS_STATUS_HW_NOT_FOUND_ERR,
	CLS_STATUS_MSG_COMMON_ERR_PREFIX "reason: entry not found"
    },
    {
	OPS_CLS_STATUS_HW_EXISTS_ERR,
	CLS_STATUS_MSG_COMMON_ERR_PREFIX "reason: entry already exist"
    },
    {
	OPS_CLS_STATUS_HW_TIMEOUT_ERR,
	CLS_STATUS_MSG_COMMON_ERR_PREFIX "reason: operation timed out"
    },
    {
	OPS_CLS_STATUS_HW_BUSY_ERR,
	CLS_STATUS_MSG_COMMON_ERR_PREFIX "reason: hardware busy"
    },
    {
	OPS_CLS_STATUS_HW_FAIL_ERR,
	CLS_STATUS_MSG_COMMON_ERR_PREFIX "reason: operation failed"
    },
    {
	OPS_CLS_STATUS_HW_DISABLED_ERR,
	CLS_STATUS_MSG_COMMON_ERR_PREFIX "reason: operation is disabled"
    },
    {
	OPS_CLS_STATUS_HW_BADID_ERR,
	CLS_STATUS_MSG_COMMON_ERR_PREFIX "reason: invalid identifier"
    },
    {
	OPS_CLS_STATUS_HW_RESOURCE_ERR,
	CLS_STATUS_MSG_COMMON_ERR_PREFIX "reason: no resource for operation"
    },
    {
	OPS_CLS_STATUS_HW_CONFIG_ERR,
	CLS_STATUS_MSG_COMMON_ERR_PREFIX "reason: invalid configuration"
    },
    {
	OPS_CLS_STATUS_HW_UNAVAIL_ERR,
	CLS_STATUS_MSG_COMMON_ERR_PREFIX "reason: feature unavailable"
    },
    {
	OPS_CLS_STATUS_HW_INIT_ERR,
	CLS_STATUS_MSG_COMMON_ERR_PREFIX "reason: feature not initialized"
    },
    {
	OPS_CLS_STATUS_HW_PORT_ERR,
	CLS_STATUS_MSG_COMMON_ERR_PREFIX "reason: invalid port"
    },
    {
	OPS_CLS_STATUS_HW_UNKNOWN_ERR,
	CLS_STATUS_MSG_COMMON_ERR_PREFIX "reason: unknown error"
    }
};

/**
 * Populats the global status table with classifier common status messages
 */
void cls_status_msgs_populate()
{
    unsigned int n_entries;
    /* populate global status table for classifier common status codes */
    n_entries = (unsigned int)
                  (sizeof(cls_status_msgs)/sizeof(cls_status_msgs[0]));
    VLOG_DBG("Populating global_status_table for %d cls_status_msg entries",
              n_entries);
    cls_status_table_populate(&cls_status_msgs[0],n_entries);
}

/*
 * Returns the classifier status message string for the specified
 * status code.
 */
void cls_status_msgs_get(enum ops_cls_list_status_code status_code,
                         const char *op_str, const char *feature_str,
                         const char *iface_str, unsigned int iface_num,
                         unsigned int seq_num,  unsigned int len,
                         char *status_msg_str)
{
    const char *status_table_str;
    char seq_num_str[CLS_STATUS_MSG_SEQ_NUM_STR_LEN];
    status_table_str = cls_status_table_get(status_code);

    if(status_table_str != NULL) {
        if(seq_num == 0) {
            /* invalid entry sequence number, so format the string without
             * entry sequence number string.
             */
            snprintf(status_msg_str,len,status_table_str,op_str,feature_str,
                     iface_str,iface_num,CLS_STATUS_MSG_SEQ_NUM_INVALID);
        } else {
            /* valid entry sequence number, so format the string using
             * entry sequence number.
             */
            snprintf(seq_num_str,CLS_STATUS_MSG_SEQ_NUM_STR_LEN,
                     CLS_STATUS_MSG_SEQ_NUM_VALID,seq_num);

            snprintf(status_msg_str,len,status_table_str,op_str,feature_str,
                     iface_str,iface_num,seq_num_str);

        } /* end if seq_num == 0 */
    } /* end if status_table_str != NULL */
}

/**
 * Debug print function to display formatted status message strings
 * @todo: Modify to accept parameters and link this to appctl framework??
 *
 */
void cls_status_msgs_dbg_print()
{
    unsigned int i, n_entries, seq_num;
    struct cls_status_entry *status_entry;
    char status_msg[STATUS_MSG_LEN] = {0};

    n_entries = (unsigned int)
                  (sizeof(cls_status_msgs)/sizeof(cls_status_msgs[0]));
    for(i = 0; i < n_entries; i++) {
        status_entry = (struct cls_status_entry *)&cls_status_msgs[i];
        if(status_entry)
        {
            seq_num = i % 2;
            cls_status_msgs_get(status_entry->status_code,
				CLS_STATUS_MSG_OP_APPLY_STR,
				CLS_STATUS_MSG_FEATURE_ACL_STR,
				CLS_STATUS_MSG_IFACE_PORT_STR,
				1,seq_num,STATUS_MSG_LEN,&status_msg[0]);
            VLOG_DBG("status_msg => %s",status_msg);
        }
    }
}

/** @} end of group cls_status_msgs */