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

#ifndef __ACL_PLUGIN_H_
#define __ACL_PLUGIN_H_  1

#include "reconfigure-blocks.h"
#include "run-blocks.h"


#define ACL_PLUGIN_NAME "acl"  /**< ACL feature plugin name */
#define ACL_PLUGIN_MAJOR 0     /**< ACL feature plugin major version */
#define ACL_PLUGIN_MINOR 1     /**< ACL feature plugin minor version */

/**
 * Bridge init callback. This function initializes the ACL feature plugin
 * data structures at the @see bridge_init() time.
 *
 * @param[in] blk_params - Pointer to the block parameter structure
 */
void acl_callback_bridge_init(struct blk_params *blk_params);

/**
 * Bridge reconfigure callback for BRIDGE_RECONFIGURE_INIT block.
 * This function checks for any modifications to ACL table on each
 * bridge reconfigure. If there are modifications, relevant changes
 * are made to PI data structures and ASIC layer is programmed if
 * necessary
 *
 * @param[in] blk_params - Pointer to block parameter structure
 */
void acl_callback_reconfigure_init(struct blk_params *blk_params);

/**
 * Initialize ofproto layer for ACL feature plugin. This function
 * finds the relevant OPS_CLS plugin extension so the feature plugin
 * can make calls into the asic plugin when required.
 */
void acl_ofproto_init();

/**
 * Bridge run callback. This function updates the in_progress column of an ACL
 * if needed.
 *
 * @param[in] blk_params - Pointer top the block parameter structure
 */
void acl_callback_run_complete(struct run_blk_params *blk_params);

#endif