/****************************************************************************
 * (c) Copyright 2015-2016 Hewlett Packard Enterprise Development LP
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

#ifndef _QOS_SCHEDULE_PROFILE_VTY_H_
#define _QOS_SCHEDULE_PROFILE_VTY_H_

/**
 * Creates the 'strict' profile, if it does not already exist.
 */
void qos_schedule_profile_create_strict_profile(
        struct ovsdb_idl_txn *txn);

/**
 * Shows the global schedule profile running config.
 */
void qos_schedule_profile_show_running_config(void);

/**
 * Returns true if the schedule profile contains the queue_num.
 */
bool qos_schedule_profile_has_queue_num(struct ovsrec_qos *profile_row,
        int64_t queue_num);

/**
 * Returns true if the schedule profile is complete.
 */
bool qos_schedule_profile_is_complete(struct ovsrec_qos *profile_row);

/**
 * Retrieves the schedule profile row.
 */
struct ovsrec_qos *qos_get_schedule_profile_row(
        const char *profile_name);

/**
 * Shows the running config for qos schedule profile.
 */
void qos_schedule_profile_show_running_config(void);

/**
 * Initializes vty functions for qos schedule profile.
 */
void qos_schedule_profile_vty_init(void);

/**
 * Initializes ovsdb functions for qos schedule profile.
 */
void qos_schedule_profile_ovsdb_init(void);

#endif /* _QOS_SCHEDULE_PROFILE_VTY_H_ */
