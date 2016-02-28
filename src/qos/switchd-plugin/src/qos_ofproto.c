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

#include <config.h>
#include "qos_ofproto.h"
#include "qos_utils.h"
#include <errno.h>
#include <string.h>
#include "smap.h"
#include "ofproto/ofproto-provider.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(qos_ofproto);


/* converts enum in qos_trust SMAP into enum value */
enum qos_trust get_qos_trust_value(const struct smap *cfg) {
    enum qos_trust rv = QOS_TRUST_MAX;
    const char *qos_trust_name = smap_get(cfg, "qos_trust");

    VLOG_DBG("qos trust is %s", qos_trust_name);
    if (qos_trust_name == NULL) {
        return rv;
    }

    if (strcmp(qos_trust_name, "dscp") == 0) {
        rv = QOS_TRUST_DSCP;
    } else if (strcmp(qos_trust_name, "cos") == 0) {
        rv = QOS_TRUST_COS;
    } else if (strcmp(qos_trust_name, "none") == 0) {
        rv = QOS_TRUST_NONE;
    }

    return rv;
}

/* sets qos (and any other qos parameter) for a port in an ofproto.
   aux is pointer to struct port */
int ofproto_set_port_qos_cfg(struct ofproto *ofproto, void *aux,
                             const enum qos_trust global_qos_trust,
                             const struct smap *qos_config,
                             const struct smap *other_config) {
    struct qos_port_settings settings = {0};
    const char *cos_override_str;
    const char *dscp_override_str;
    int rv = 0;

#ifdef REWRITE_ME
    if (ofproto->ofproto_class->set_port_qos_cfg == NULL) {
        return EOPNOTSUPP;
    }
#endif

    VLOG_DBG("%s: aux @ %p, qos_trust %d, qos_cfg smap@ %p",
             __FUNCTION__, aux, global_qos_trust, qos_config);

    /* Set port qos trust.  If port has no setting, use global default */
    settings.qos_trust = get_qos_trust_value(qos_config);
    if (settings.qos_trust == QOS_TRUST_MAX) {
       settings.qos_trust = global_qos_trust;
    }
    if (settings.qos_trust == QOS_TRUST_MAX) {
        return EOPNOTSUPP;
    }

    /* check for COS or DSCP overrides */
    cos_override_str = smap_get(qos_config, QOS_COS_OVERRIDE_KEY);
    if (cos_override_str != NULL) {
        settings.cos_override_enable = true;
        settings.cos_override_value = strtoul(cos_override_str, NULL, 0);
    }
    dscp_override_str = smap_get(qos_config, QOS_DSCP_OVERRIDE_KEY);
    if (dscp_override_str != NULL) {
        settings.dscp_override_enable = true;
        settings.dscp_override_value = strtoul(dscp_override_str, NULL, 0);
    }

    settings.other_config = other_config;
    VLOG_DBG("... qos trust %d, override cos:%c%d dscp:%c%d, other_cfg smap@ %p",
             settings.qos_trust,
             (settings.cos_override_enable) ? 'T' : 'F',
             settings.cos_override_value,
             (settings.dscp_override_enable) ? 'T' : 'F',
             settings.dscp_override_value,
             other_config);

#ifdef REWRITE_ME
    rv = ofproto->ofproto_class->set_port_qos_cfg(ofproto, aux, &settings);
#endif

    return rv;
}

/* sets COS map in an ofproto.  aux currently unused */
int ofproto_set_cos_map(struct ofproto *ofproto, void *aux,
                        const struct cos_map_settings *settings) {
    int rv = 0;

#ifdef REWRITE_ME
    if (ofproto->ofproto_class->set_cos_map == NULL) {
        return EOPNOTSUPP;
    }
#endif

    VLOG_DBG("%s: aux @ %p, settings@ %p (%d entry(s))",
             __FUNCTION__, aux, settings, settings->n_entries);

#ifdef REWRITE_ME
    rv = ofproto->ofproto_class->set_cos_map(ofproto, aux, settings);
#endif

    return rv;
}

/* sets DSCP map in an ofproto.  aux currently unused */
int ofproto_set_dscp_map(struct ofproto *ofproto, void *aux,
                         const struct dscp_map_settings *settings) {
    int rv = 0;

#ifdef REWRITE_ME
    if (ofproto->ofproto_class->set_dscp_map == NULL) {
        return EOPNOTSUPP;
    }
#endif

    VLOG_DBG("%s: aux @ %p, settings@ %p (%d entry(s)",
             __FUNCTION__, aux, settings, settings->n_entries);

#ifdef REWRITE_ME
    rv = ofproto->ofproto_class->set_dscp_map(ofproto, aux, settings);
#endif

    return rv;
}

int ofproto_apply_qos_profile(struct ofproto *ofproto,
                              const void *aux,
                              const struct schedule_profile_settings *s_settings,
                              const struct queue_profile_settings *q_settings) {
    int rv = 0;

    VLOG_DBG("%s aux=%p settings=%p,%p", __FUNCTION__, aux,
             s_settings, q_settings);
#ifdef REWRITE_ME
    if (ofproto->ofproto_class->apply_qos_profile == NULL) {
        return EOPNOTSUPP;
    }
#endif

#ifdef REWRITE_ME
    rv = ofproto->ofproto_class->apply_qos_profile(ofproto,
                                                       aux,
                                                       s_settings,
                                                       q_settings);
#endif

    return rv;
}
