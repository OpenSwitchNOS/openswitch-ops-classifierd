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

#ifndef _QOS_PROFILE_H_
#define _QOS_PROFILE_H_

#include "vswitch-idl.h"
#include "ofproto/ofproto-provider.h"


/* OVSDB IDL used to obtain configuration. */
extern struct ovsdb_idl *idl;

/* Most recently processed IDL sequence number. */
extern unsigned int idl_seqno;


int qos_apply_profile(struct ofproto *ofproto,
                      const void *aux, /* struct port *port */
                      const struct ovsrec_qos *ovsrec_qos,
                      const struct ovsrec_q_profile *ovsrec_q_profile);
void qos_configure_profiles(struct ofproto *ofproto,
                            const struct ovsrec_port *port_cfg,
                            const void *aux /* struct port *port */);

#endif /* _QOS_PROFILE_H_ */
