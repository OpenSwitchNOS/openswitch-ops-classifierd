/*
 * (C) Copyright 2016 Hewlett Packard Enterprise Development LP
 *
 *   Licensed under the Apache License, Version 2.0 (the "License"); you may
 *   not use this file except in compliance with the License. You may obtain
 *   a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *   License for the specific language governing permissions and limitations
 *   under the License.
 */

#ifndef _OPS_CLASSIFIERD_H_

#define _OPS_CLASSIFIERD_H_

#include <openvswitch/vlog.h>
#include <openvswitch/compiler.h>

#define STR_EQ(s1, s2)      ((strlen((s1)) == strlen((s2))) && (!strncmp((s1), (s2), strlen((s2)))))

extern void classifierd_ovsdb_init(const char *db_path);
extern void classifierd_ovsdb_exit(void);
extern void classifierd_run(void);
extern void classifierd_wait(void);
extern void classifierd_debug_dump(struct ds *ds, int argc, const char *argv[]);

#endif /* _CLASSIFIERD_H_ */
