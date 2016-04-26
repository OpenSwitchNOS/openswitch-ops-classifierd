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

#include <stddef.h>
#include "vswitch-idl.h"
#include "acl_db_util.h"

/**
 * Global array of groups of DB access routines. There will be one entry
 * in this array per (type, direction) pair of an ACL. This array is used
 * by the switchd plugin to access the quartet columns of ovsrec_port row
 * for a given (type, direction) type easily.
 */
struct acl_db_util acl_db_accessor[ACL_CFG_MAX_TYPES];

/**
 * Macro to populate the acl_db_accessor global array at switchd-plugin
 * init time.
 */
#define ASSIGN_ACL_DB_ACCESSOR(idx, type_arg, direction_arg, base) \
    acl_db_accessor[idx].type = type_arg;                                 \
    acl_db_accessor[idx].direction = direction_arg;                       \
    acl_db_accessor[idx].column_applied = \
                                    &ovsrec_port_col_##base##_applied;      \
    acl_db_accessor[idx].column_cfg = &ovsrec_port_col_##base##_cfg;    \
    acl_db_accessor[idx].column_cfg_version = \
                                  &ovsrec_port_col_##base##_cfg_version; \
    acl_db_accessor[idx].column_cfg_status =\
                                        &ovsrec_port_col_##base##_status; \
    acl_db_accessor[idx].offset_applied = \
                            offsetof(struct ovsrec_port, base##_applied); \
    acl_db_accessor[idx].offset_cfg = \
                            offsetof(struct ovsrec_port, base##_cfg); \
    acl_db_accessor[idx].offset_cfg_version = \
                        offsetof(struct ovsrec_port, base##_cfg_version); \
    acl_db_accessor[idx].offset_cfg_status = \
                        offsetof(struct ovsrec_port, base##_status); \
    acl_db_accessor[idx].set_applied = \
                                ovsrec_port_set_##base##_applied;      \
    acl_db_accessor[idx].set_cfg = ovsrec_port_set_##base##_cfg;        \
    acl_db_accessor[idx].set_cfg_version = \
                                   ovsrec_port_set_##base##_cfg_version; \
    acl_db_accessor[idx].set_cfg_status = ovsrec_port_set_##base##_status

void
acl_db_util_init(void) {
    /* Create a global array entry for (aclv4, in) pair. */
    ASSIGN_ACL_DB_ACCESSOR(0, OPS_CLS_ACL_V4, OPS_CLS_DIRECTION_IN, aclv4_in);
}

/***** Getters *****/
#define MEMBER_AT_OFFSET(objptr, offset, type) \
    *(type*)(CONST_CAST(char*, (const char *)(objptr) + (offset)))

const struct ovsrec_acl*
acl_db_util_get_applied(const struct acl_db_util *acl_db,
                        const struct ovsrec_port *port)
{
    return MEMBER_AT_OFFSET(port, acl_db->offset_applied,
                            const struct ovsrec_acl*);
}

const struct ovsrec_acl*
acl_db_util_get_cfg(const struct acl_db_util *acl_db,
                      const struct ovsrec_port *port)
{
    return MEMBER_AT_OFFSET(port, acl_db->offset_cfg,
                            const struct ovsrec_acl*);
}

int64_t
acl_db_util_get_cfg_version(const struct acl_db_util *acl_db,
                              const struct ovsrec_port *port)
{
    return MEMBER_AT_OFFSET(port, acl_db->offset_cfg_version, int64_t);
}

const struct smap*
acl_db_util_get_cfg_status(const struct acl_db_util *acl_db,
                             const struct ovsrec_port *port)
{
    return MEMBER_AT_OFFSET(port, acl_db->offset_cfg_status,
                            const struct smap*);
}


/***** Setters *****/
void
acl_db_util_set_applied(const struct acl_db_util *acl_db,
                        const struct ovsrec_port *port,
                        const struct ovsrec_acl *cur)
{
    (*acl_db->set_applied)(port, cur);
}

void
acl_db_util_set_cfg(const struct acl_db_util *acl_db,
                      const struct ovsrec_port *port,
                      const struct ovsrec_acl *cfg)
{
    (*acl_db->set_cfg)(port, cfg);
}

void
acl_db_util_set_cfg_status(const struct acl_db_util *acl_db,
                             const struct ovsrec_port *port,
                             const struct smap *cfg_status)
{
    (*acl_db->set_cfg_status)(port, cfg_status);
}