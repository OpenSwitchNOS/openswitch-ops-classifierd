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

#ifndef __OPS_CLS_STATUS_MSGS_H__
#define __OPS_CLS_STATUS_MSGS_H__

#define OPS_CLS_STATUS_MSG_MAX_LEN 512  /**< status msg max length */
#define OPS_CLS_VERSION_STR_MAX_LEN 25 /**< Version string max length */
#define OPS_CLS_CODE_STR_MAX_LEN    15 /**< Code string max length */

/* Following macros define the strings that are used by the db
 * in status smap column
 * @todo it would be nice to have these string generated by idl based
 * on the schema.
 */
#define OPS_CLS_STATUS_STR     \
                "status_string"  /**< "status_str" string for status smap    */
#define OPS_CLS_STATUS_VERSION_STR     \
                "version"        /**< "version" string for status smap    */
#define OPS_CLS_STATUS_STATE_STR       \
                "state"          /**< "state" string for status smap      */
#define OPS_CLS_STATUS_CODE_STR        \
                "code"           /**< "code" string for status smap       */
#define OPS_CLS_STATUS_MSG_STR         \
                "message"        /**< "message" string for status smap    */
#define OPS_CLS_STATE_APPLIED_STR      \
                "applied"        /**< "applied" string for state smap     */
#define OPS_CLS_STATE_REJECTED_STR     \
                "rejected"       /**< "rejected" string for state smap    */
#define OPS_CLS_STATE_IN_PROGRESS_STR  \
                "in_progress"    /**< "in_progress" string for state smap */
#define OPS_CLS_STATE_CANCELLED_STR    \
                "cancelled"      /**< "cancelled" string for state smap   */

/* Following macros define the strings that can be used by the
 * callers to fill in variable operation str in ops_cls_status_msgs
 */
#define OPS_CLS_STATUS_MSG_OP_APPLY_STR    \
                "apply"         /**< string to display apply operation    */
#define OPS_CLS_STATUS_MSG_OP_REMOVE_STR   \
                "remove"        /**< string to display remove operation   */
#define OPS_CLS_STATUS_MSG_OP_REPLACE_STR  \
                "replace"       /**< string to display replace operation  */
#define OPS_CLS_STATUS_MSG_OP_UPDATE_STR   \
                "update"        /**< string to display update operation   */
#define OPS_CLS_STATUS_MSG_OP_GET_STR      \
                "get"           /**< string to display get operation      */
#define OPS_CLS_STATUS_MSG_OP_CLEAR_STR    \
                "clear"         /**< string to display clear operation    */
#define OPS_CLS_STATUS_MSG_OP_CLEARALL_STR   \
                "clear all"     /**< string to display clearall operation */

/* Following macros define the strings that can be used by the
 * callers to fill in variable feature str in ops_cls_status_msgs
 */
#define OPS_CLS_STATUS_MSG_FEATURE_ACL_STR       \
             "acl"            /**< string to display acl feature            */
#define OPS_CLS_STATUS_MSG_FEATURE_ACLLIST_STR   \
             "acl list"       /**< string to display acl list feature       */
#define OPS_CLS_STATUS_MSG_FEATURE_ACL_STAT_STR  \
             "acl statistics" /**< string to display acl statistics feature */

/* Following macros define the strings that can be used by the
 * callers to fill in variable interface type str in ops_cls_status_msgs
 */
#define OPS_CLS_STATUS_MSG_IFACE_PORT_STR  "port"  /**< string to display port
                                                        iface type          */
/**
 * Populates the global status table with classifier common status messages
 */
void ops_cls_status_msgs_populate(void);

/**
 * Returns the classifier status message string for the given status code
 *
 * @param[in]  status_code for which status string to be retrieved
 * @param[in]  op_str string representing classifier operation. Following
 *             macros should be used by the callers
 *                - OPS_CLS_STATUS_MSG_OP_APPLY_STR
 *                - OPS_CLS_STATUS_MSG_OP_REMOVE_STR
 *                - OPS_CLS_STATUS_MSG_OP_REPLACE_STR
 *                - OPS_CLS_STATUS_MSG_OP_UPDATE_STR
 *                - OPS_CLS_STATUS_MSG_OP_GET_STR
 *                - OPS_CLS_STATUS_MSG_OP_CLEAR_STR
 *                - OPS_CLS_STATUS_MSG_OP_CLEARALL_STR
 * @param[in]  feature_str string representing classifier feature. Following
 *             macros should be used by the callers.
 *                - OPS_CLS_STATUS_MSG_FEATURE_ACL_STR
 *                - OPS_CLS_STATUS_MSG_FEATURE_ACL_LIST_STR
 *                - OPS_CLS_STATUS_MSG_FEATURE_ACL_STATS_STR
 * @param[in]  iface_str string representing interface type, following macros
 *             should be used by the callers
 *                - OPS_CLS_STATUS_MSG_IFACE_PORT_STR
 * @param[in]  iface_num interface number on which classifier feature operation
 *             was performed
 * @param[in]  sequence_num valid entry sequence number if applicable,otherwise
 *             caller must pass 0
 * @param[in]  len length of the output msg_str buffer
 * @param[out] status_msg_str formatted status message string will be written
 *             to this variable
 *
 */
void ops_cls_status_msgs_get(enum ops_cls_list_status_code status_code,
                         const char *op_str, const char *feature_str,
                         const char *iface_str, const char *iface_num,
                         unsigned int seq_num,  unsigned int len,
                         char *status_msg_str);

#endif  /* __OPS_CLS_STATUS_MSGS_H__ */
