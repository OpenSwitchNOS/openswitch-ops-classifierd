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

#ifndef _QOS_TRUST_H_
#define _QOS_TRUST_H_

#include "qos_ofproto.h"
#include "vswitch-idl.h"
#include "ofproto/ofproto-provider.h"


/* OVSDB IDL used to obtain configuration. */
extern struct ovsdb_idl *idl;

/* Most recently processed IDL sequence number. */
extern unsigned int idl_seqno;


bool qos_configure_trust(void);
void qos_set_port_qos_cfg(struct ofproto *ofproto,
                          void *aux, /* struct port * */
                          struct ovsrec_port *port_cfg);

#endif /* _QOS_TRUST_H_ */
