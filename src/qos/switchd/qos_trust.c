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

#include <openvswitch/vlog.h>
#include "qos_trust.h"
#include "qos_utils.h"


VLOG_DEFINE_THIS_MODULE(qos_trust);

/* Global QOS trust state. */
static enum qos_trust global_qos_trust = QOS_TRUST_NONE;


/* Configure global QOS trust setting. */
bool
qos_configure_trust(void)
{
    enum qos_trust qos_trust;
    const struct ovsrec_system *ovs_row = NULL;
    bool changed = false;


    // nothing to do if System row is unchanged.
    ovs_row = ovsrec_system_first(idl);
    if (OVSREC_IDL_IS_ROW_MODIFIED(ovs_row, idl_seqno) ||
        OVSREC_IDL_IS_ROW_INSERTED(ovs_row, idl_seqno))
    {
        qos_trust = get_qos_trust_value(&ovs_row->qos_config);

        // only change saved QoS trust if default is valid
        if (qos_trust != QOS_TRUST_MAX) {
            if (qos_trust != global_qos_trust)
            {
                changed = true;
                global_qos_trust = qos_trust;
            }
        }
    }

    return changed;
}

void
qos_set_port_qos_cfg(struct ofproto *ofproto,
                     void *aux, /* struct port * */
                     struct ovsrec_port *port_cfg) {

    ofproto_set_port_qos_cfg(ofproto,
                             aux,
                             global_qos_trust,
                             &port_cfg->qos_config,
                             &port_cfg->other_config);
}
