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
 *
 *
 * Control Plane Policing (COPP) SwitchD ASIC Provider API
 *
 * Declares the functions and data structures that are used between the
 * SwitchD COPP feature and ASIC-specific providers.
 */


#ifndef COPP_TEMP_KEYS_H
#define COPP_TEMP_KEYS_H 1

#ifdef  __cplusplus
extern "C" {
#endif


/*
 * Use designated initializer to pre-fill an array of pointer to key names
 * for each enum use by the API.
 */


const char *const temp_copp_keys[];

#define TEMP_COPP_STATS_BUF_FMT "%lu,%lu,%lu,%lu,%lu,%lu,%lu "
#define TEMP_COPP_STATS_VARS(h, c)         \
        h.rate, h.burst, h.local_priority,  \
        c.packets_passed, c.bytes_passed,   \
        c.packets_dropped, c.bytes_dropped

#endif /* COPP_TEMP_KEYS_H */
