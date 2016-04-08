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

#ifndef __CLS_STATUS_MSGS_H__
#define __CLS_STATUS_MSGS_H__


#define CLS_STATUS_MSG_OP_APPLY_STR    "apply"     /**< string to display
                                                     apply operation */
#define CLS_STATUS_MSG_OP_REMOVE_STR   "remove"    /**< string to display
                                                     remove operation */
#define CLS_STATUS_MSG_OP_REPLACE_STR  "replace"   /**< string to display
                                                     replace operation */
#define CLS_STATUS_MSG_OP_UPDATE_STR   "update"    /**< string to display
                                                     update operation */
#define CLS_STATUS_MSG_OP_GET_STR      "get"       /**< string to display
                                                     get operation */
#define CLS_STATUS_MSG_OP_CLEAR_STR    "clear"     /**< string to display
                                                     clear operation */
#define CLS_STATUS_MSG_OP_CLEARALL_STR "clear all" /**< string to display
                                                     clearall operation */


#define CLS_STATUS_MSG_FEATURE_ACL_STR       "acl" /**< string to display acl
                                                       feature */
#define CLS_STATUS_MSG_FEATURE_ACLLIST_STR   "acl list" /**< string to display
                                                         acl list feature */
#define CLS_STATUS_MSG_FEATURE_ACL_STAT_STR  "acl statistics" /**< string to
                                                               display acl
                                                               statistics
                                                               feature */

#define CLS_STATUS_MSG_IFACE_PORT_STR  "port"  /**< string to display port
                                                    iface type */
/**
 * Populats the global status table with classifier common status messages
 */
extern void cls_status_msgs_populate(void);

/**
 * Returns the classifier status message string for the given status code
 *
 * @param[in]  status_code for which status string to be retrieved
 * @param[in]  op_str string representing classifier operation. Following
 *             macros should be used by the callers
 *                - CLS_STATUS_MSG_OP_APPLY_STR
 *                - CLS_STATUS_MSG_OP_REMOVE_STR
 *                - CLS_STATUS_MSG_OP_REPLACE_STR
 *                - CLS_STATUS_MSG_OP_UPDATE_STR
 *                - CLS_STATUS_MSG_OP_GET_STR
 *                - CLS_STATUS_MSG_OP_CLEAR_STR
 *                - CLS_STATUS_MSG_OP_CLEARALL_STR
 * @param[in]  feature_str string representing classifier feature. Following
 *             macros should be used by the callers.
 *                - CLS_STATUS_MSG_FEATURE_ACL_STR
 *                - CLS_STATUS_MSG_FEATURE_ACL_LIST_STR
 *                - CLS_STATUS_MSG_FEATURE_ACL_STATS_STR
 * @param[in]  iface_str string representing interface type, following macros
 *             should be used by the callers
 *                - CLS_STATUS_MSG_IFACE_PORT_STR
 * @param[in]  iface_num interface number on which classifier feature operation
 *             was performed
 * @param[in]  sequence_num valid entry sequence number if applicable, otherwise
 *             caller must pass 0
 * @param[in]  len length of the output msg_str buffer
 * @param[out] status_msg_str formatted status message string will be written
 *             to this variable
 *
 */
extern void cls_status_msgs_get(enum ops_cls_list_status_code status_code,
                         const char *op_str, const char *feature_str,
                         const char *iface_str, unsigned int iface_num,
                         unsigned int seq_num,  unsigned int len,
                         char *status_msg_str);

/**
 * Debug print function to display formatted status message strings
 * @todo: Modify to accept parameters and link this to appctl framework??
 *
 */
extern void cls_status_msgs_dbg_print(void);

#endif  /* __CLS_STATUS_MSGS_H__ */
