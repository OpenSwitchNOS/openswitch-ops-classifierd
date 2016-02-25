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

#include <pwd.h>
#include <readline/history.h>
#include <readline/readline.h>
#include <setjmp.h>
#include <sys/un.h>
#include <sys/wait.h>

#include "openswitch-idl.h"
#include "openvswitch/vlog.h"
#include "ovsdb-idl.h"
#include "qos_utils.h"
#include "smap.h"
#include "vswitch-idl.h"

/**
 * This is an empty placeholder. If this function is removed, and then this
 * file is removed, then there is a build error, since there are no .c files
 * to compile in this directory.
 */
void qos_utils_placeholder(void) {
    return;
}
