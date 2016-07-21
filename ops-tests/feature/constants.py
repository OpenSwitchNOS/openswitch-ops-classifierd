topology_1switch = """
#+--------+
#|  ops1  |
#+--------+

#Nodes
[type=openswitch name="openswitch 1"] ops1
"""

topology_1switch_2host = """
# +-------+                    +-------+
# |       |     +--------+     |       |G
# |  hs1  <----->  ops1  <----->  hs2  |
# |       |     +--------+     |       |
# +-------+                    +-------+

# Nodes
# [image="fs-genericx86-64:latest" \
# type=openswitch name="OpenSwitch 1"] ops1
# [type=host name="Host 1" image="openswitch/ubuntuscapy:latest"] hs1
# [type=host name="Host 2" image="openswitch/ubuntuscapy:latest"] hs2
[type=openswitch name="Switch 1"] ops1
[type=host name="Host 1" image="Ubuntu"] hs1
[type=host name="Host 2" image="Ubuntu"] hs2

# Links
hs1:1 -- ops1:1
ops1:6 -- hs2:1
"""

topology_2switch_2host_lag = """
# +-------+                                     +-------+
# |       |     +--------+     +-------+        |       |
# | host1 <-----> switch1 <---->switch2<------->| host2 |
# |       |     +--------+     +-------+        |       |
# +-------+                                     +-------+

#Nodes
[type=openswitch name="openswitch 1"] ops1
[type=openswitch name="openswitch 2"] ops2
[type=host name="Host 1"] hs1
[type=host name="Host 2"] hs2

#Links
hs1:1 -- ops1:1
ops1:5 -- ops2:5
ops1:6 -- ops2:6
ops2:1 -- hs2:1
"""

topology_2switch_2host = """
# +-------+                                     +-------+
# |       |     +--------+     +-------+        |       |
# | host1 <-----> switch1 <---->switch2<------->| host2 |
# |       |     +--------+     +-------+        |       |
# +-------+                                     +-------+

#Nodes
[type=openswitch name="openswitch 1"] ops1
[type=openswitch name="openswitch 2"] ops2
[type=host name="Host 1"] hs1
[type=host name="Host 2"] hs2

#Links
hs1:1 -- ops1:1
ops1:6 -- ops2:6
ops2:1 -- hs2:1
"""
