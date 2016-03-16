/*
 * Copyright (c) 2016 Hewlett Packard Enterprise Development LP
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

#ifndef QOS_OFPROTO_H
#define QOS_OFPROTO_H 1

#include "smap.h"
#include "ofproto/ofproto.h"

#ifdef  __cplusplus
extern "C" {
#endif


/* in System or Port table, possible values in qos_config column */
enum qos_trust {
    QOS_TRUST_NONE = 0,
    QOS_TRUST_COS,
    QOS_TRUST_DSCP,
    QOS_TRUST_MAX /* Used for validation only! */
};

/* collection of parameters to set_port_qos_cfg API */
struct qos_port_settings {
    enum qos_trust  qos_trust;
    bool            cos_override_enable;
    bool            dscp_override_enable;
    uint8_t         cos_override_value;
    uint8_t         dscp_override_value;
    const struct smap *other_config;
};

/* in QoS_DSCP_Map or QoS_COS_Map, possible values for color column */
enum cos_color {
    COS_COLOR_GREEN = 0,
    COS_COLOR_YELLOW,
    COS_COLOR_RED,
    COS_COLOR_MAX
};

/* single row from QoS_DSCP_Map table */
struct dscp_map_entry {
    enum cos_color  color;
    int codepoint;
    int local_priority;
    int cos;
    struct smap *other_config;
};

/* 1 or more rows in QoS_DSCP_Map passed to set_dscp_map API */
struct dscp_map_settings {
    int n_entries;
    struct dscp_map_entry *entries;   /* array of 'struct dscp_map_entry' */
};

/* single row from QoS_COS_Map table */
struct cos_map_entry {
    enum cos_color color;
    int codepoint;
    int local_priority;
    struct smap *other_config;
};

/* 1 or more rows in QoS_COS_Map passed to set_cos_map API */
struct cos_map_settings {
    int n_entries;
    struct cos_map_entry *entries;   /* array of 'struct cos_map_entry' */
};

struct local_priority_entry {
    unsigned local_priority;  /* Number */
    /* TBD: ECN, CAP threshold, et.al. WRED parameters */
};

enum qos_queue_profile_mode {
    QUEUE_PROFILE_DEFAULT = 0,
    QUEUE_PROFILE_LOSSLESS,
    QUEUE_PROFILE_LOW_LATENCY,
    QUEUE_PROFILE_MAX /* Used for validation only! */
};

/* single queue-profile row (from Q_Profile->Q_Settings table) */
struct queue_profile_entry {
    unsigned queue;              /* queue number */
    int n_local_priorities;      /* length of local_priorities array, may be 0 */
    struct local_priority_entry **local_priorities; /* variable-length array of */
                                                    /* 'struct local_priority_entry' */
                                                    /* ptrs. May be NULL */
    enum qos_queue_profile_mode mode;
    struct smap *other_config;   /* pass-through from Q_Settings row */
    /* TBD: min & max shaping parameters */
};

/* 1 or more rows in Q_Profile passed to set_queue_profile API */
struct queue_profile_settings {
    int n_entries;
    struct queue_profile_entry **entries; /* variable-length array of */
                                          /* 'struct queue_profile_entry' */
                                          /* ptrs. May be NULL */
    struct smap *other_config;   /* pass-through from Q_Profile row */
};

enum schedule_algorithm {
    ALGORITHM_STRICT,
    ALGORITHM_WRR,
    ALGORITHM_MAX
};

/* single schedule-profile row (from QoS->Queue table) */
struct schedule_profile_entry {
    unsigned queue;            /* queue number */
    enum schedule_algorithm algorithm; /* must have some scheduling algorithm */
    int weight;                /* weight, if queue type is WRR */
    struct smap *other_config; /* pass-through from Queue row */
};

/* 1 or more rows in QoS passed to set_schedule_profile API */
struct schedule_profile_settings {
    int     n_entries;
    struct schedule_profile_entry **entries; /* variable-length array of */
                                             /* 'struct schedule_profile_entry' */
                                             /* ptrs. May be NULL */
    /* TBD: scheduling type */
    struct smap *other_config;   /* pass-through from QoS row */
};

/* Configuration of QOS tables. */
enum qos_trust get_qos_trust_value(const struct smap *);
int ofproto_set_port_qos_cfg(struct ofproto *,
                             void *,
                             const enum qos_trust,
                             const struct smap *,
                             const struct smap *);
int ofproto_set_cos_map(struct ofproto *, void *,
                        const struct cos_map_settings *);
int ofproto_set_dscp_map(struct ofproto *, void *,
                         const struct dscp_map_settings *);
int ofproto_apply_qos_profile(struct ofproto *,
                              const void *,
                              const struct schedule_profile_settings *,
                              const struct queue_profile_settings *);


#ifdef  __cplusplus
}
#endif

#endif /* qos_ofproto.h */
