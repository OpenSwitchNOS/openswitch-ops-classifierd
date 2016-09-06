# -*- coding: utf-8 -*-
#
# Copyright (C) 2016 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

topology_1switch_def = """
#+--------+
#|  ops1  |
#+--------+

# Nodes
[type=openswitch name="openswitch 1"] ops1
"""

topology_1switch_2host_def = """
# +-------+                    +-------+
# |       |     +--------+     |       |
# |  hs1  <----->  ops1  <----->  hs2  |
# |       |     +--------+     |       |
# +-------+                    +-------+

# Nodes
[type=openswitch name="Switch 1"] ops1
[type=host name="Host 1"] hs1
[type=host name="Host 2"] hs2

# Links
hs1:if01 -- ops1:if01
ops1:if06 -- hs2:if01
"""

topology_2switch_2host_lag_def = """
# +-------+                                     +-------+
# |       |     +--------+     +-------+        |       |
# | host1 <-----> switch1 <---->switch2<------->| host2 |
# |       |     +--------+     +-------+        |       |
# +-------+                                     +-------+

# Nodes
[type=openswitch name="openswitch 1"] ops1
[type=openswitch name="openswitch 2"] ops2
[type=host name="Host 1"] hs1
[type=host name="Host 2"] hs2

# Links
hs1:if01 -- ops1:if01
ops1:if05 -- ops2:if05
ops1:if06 -- ops2:if06
ops2:if01 -- hs2:if01
"""

topology_2switch_2host_def = """
# +-------+                                     +-------+
# |       |     +--------+     +-------+        |       |
# | host1 <-----> switch1 <---->switch2<------->| host2 |
# |       |     +--------+     +-------+        |       |
# +-------+                                     +-------+

# Nodes
[type=openswitch name="openswitch 1"] ops1
[type=openswitch name="openswitch 2"] ops2
[type=host name="Host 1"] hs1
[type=host name="Host 2"] hs2

# Links
hs1:if01 -- ops1:if01
ops1:if06 -- ops2:if06
ops2:if01 -- hs2:if01
"""
