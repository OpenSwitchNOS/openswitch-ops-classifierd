# High level design of Access Control Lists (ACL)

## Contents

- [Feature Overview](#feature-overview)
- [Design choices](#design-choices)
- [Participating modules](#participating-modules)
  - [CLI/UI/Management Interface](#cliuimanagement-interface)
  - [CoPP](#copp)
  - [ops-intfd](#ops-intfd)
  - [ops-classifierd](#ops-classifierd)
  - [ops-switchd](#ops-switchd)
- [OVSDB-Schema](#ovsdb-schema)
  - [ACL Table](#acl-table)
    - [name](#name)
    - [list_type](#listtype)
    - [cur_aces](#curaces)
    - [cfg_aces](#cfgaces)
    - [in\_ progress\_ aces](#inprogressaces)
    - [cfg_version](#cfgversion)
    - [status](#status)
  - [ACL_Entry Table](#aclentry-table)
    - [comment](#comment)
    - [action](#action)
    - [src_ip](#srcip)
    - [dst_ip](#dstip)
    - [protocol](#protocol)
    - [src \_l4 \_port \_min](#srcl4portmin)
    - [src \_l4 \_port \_max](#srcl4portmax)
    - [src \_l4 \_port \_range \_reverse](#srcl4portrangereverse)
    - [dst \_l4 \_port \_min](#dstl4portmin)
    - [dst \_l4 \_port \_max](#dstl4portmax)
    - [dst \_l4 \_port \_range \_reverse](#dstl4portrangereverse)
    - [log](#log)
    - [count](#count)
  - [Interface Table](#interface-table)
  - [Port Table](#port-table)
    - [aclv4 \_in \_applied](#aclv4inapplied)
    - [aclv4 \_in \_cfg](#aclv4incfg)
    - [aclv4 \_in \_cfg \_version](#aclv4incfgversion)
    - [aclv4 \_in \_status](#aclv4instatus)
    - [aclv4 \_in \_statistics](#aclv4instatistics)
- [References](#references)
## Feature Overview
An Access Control List (ACL) is a sequential list of statements comprised of match attributes and actions.  A packet is matched sequentially against the entries in the ACL. When a match is made the action of that entry is taken (permit or deny, log, count) and no more comparisons are made.

The initial release of ACLs will support the following:

IPv4 ACLs applied ingress to L2 and L3 ports.

ACE parameters supported:

- action: permit or deny
- source IPv4 Address: X.X.X.X/X.X.X.X
- destination IPv4 Address: X.X.X.X/X.X.X.X
- IPv4 protocol
- source L4 port or range
- destination L4 port or range
- logging of packets that match deny entries
- count

Limitations:

- ACLs: 512
- ACEs: 1024

Hardware resources are not utilized by ACLs until the ACL is applied.  If there are not enough hardware resources available to configure the entire ACL including specified counters, the application of the entire ACL will fail.

Possible future extensions:

- IPv4 ACLs applied egress to L2 and L3 ports
- IPv4 ACLs applied ingress and egress to LAGs
- IPv4 ACLs applied ingress and egress to VLANs
- IPv6 ACLs applied ingress and egress to L2 and L3 ports, LAGs and VLANs
- logging of packets that match permit entries
- MAC ACLs applied ingress and egress to L2 and L3 ports, LAGs and VLANs

## Design choices
A key design principle for the ACL implementation is the need to be able to fail the application of an ACL to an interface or fail the modification of an applied ACL.  Another design principle is the need to handle multiple user interfaces modifying the same ACL. This was achieved with the use of a number of columns in the database.

ACL Table - columns to handle modification of an applied ACL:

- cur\_aces: represents the successful version of the ACL whether or not it is applied in hardware
- cfg\_aces: represents the desired version of the ACL
- in\_progress\_aces: represents the in flight version of the ACL, success has not yet been determined,
- cfg\_version: represents the version of the ACL as defined in the cfg\_aces column
- status: key/value pairs of status fields (see below) associated with the cfg\_version of the ACL.
- in\_progress\_version: represents the version of the ACL (as defined by cfg\_aces\_version) currently being processed by switchd.

Sequence of one UI adding an ACL entry to an ACL

```ditaa

    +-------------------------------------------------+------------+--------------+-------------+------------------+---------------------+------------------+
    | event                                           | cur_aces   | cfg_aces     | cfg_version | in_progress_aces | in_progress_version | status           |
    +-------------------------------------------------+------------+--------------+-------------+------------------+---------------------+------------------+
    | UI after successful ACL applied                 | 10, 20     |  10, 20      |      1      |                  |                     | 1: applied       |
    +-------------------------------------------------+------------+--------------+-------------+------------------+---------------------+------------------+
    | UI 1 add entry	                              | 10, 20     |  10, 20, 30  |      2      |                  |                     | 1: applied       |
	+-------------------------------------------------+------------+--------------+-------------+------------------+---------------------+------------------+
	| ops-classifierd updates in_progress_aces/ver    | 10, 20     |  10, 20, 30  |      2      |  10, 20, 30      |          2          | 2: in_progress   |
	+-------------------------------------------------+------------+--------------+-------------+------------------+---------------------+------------------+
	| switchd sends UI 1 ACL to hw                    | 10, 20     |  10, 20, 30  |      2      |  10, 20, 30      |          2          | 2: in_progress   |
	+-------------------------------------------------+------------+--------------+-------------+------------------+---------------------+------------------+
	| switchd updates status, cur_aces,               |            |              |             |                  |                     |                  |
	| clears in_progress_aces/ver                     | 10, 20, 30 |  10, 20, 30  |      2      |                  |                     | 2: applied       |
	+-------------------------------------------------+------------+--------------+-------------+------------------+---------------------+------------------+

```

Sequence of two UIs adding an ACL entry to an ACL
```ditaa

    +------------------------------------------------+----------------+-----------------+--------------------+---------------+---------------------+
    | event                                          | cur_aces       | cfg_aces        |  in_progress_aces  | cfg_version   |  status             |
    +------------------------------------------------+----------------+-----------------+--------------------+---------------+---------------------+
    |UI after successful ACL applied                 | 10, 20         |  10, 20         |                    |      1        |  1: applied         |
    +------------------------------------------------+----------------+-----------------+--------------------+---------------+---------------------+
    |UI 1 add entry                                  | 10, 20         |  10, 20, 30     |                    |      2        |  1: applied         |
    +------------------------------------------------+----------------+-----------------+--------------------+---------------+---------------------+
    |switchd IDL batch 1                             | 10, 20         |  10, 20, 30     |    10, 20, 30      |      2        |  2: in_progress     |
    +------------------------------------------------+----------------+-----------------+--------------------+---------------+---------------------+
    |UI 2 add entry                                  | 10, 20         |  10, 20, 30, 40 |    10, 20, 30      |      3        |  2: in_progress     |
    +------------------------------------------------+----------------+-----------------+--------------------+---------------+---------------------+
    |switchd IDL batch 2                             | 10, 20         |  10, 20, 30, 40 |    10, 20, 30, 40  |      3        |  3: in_progress     |
    +------------------------------------------------+----------------+-----------------+--------------------+---------------+---------------------+
    |switchd IDL batch 2 sends ACL to hw             | 10, 20         |  10, 20, 30, 40 |    10, 20, 30, 40  |      3        |  3: in_progress     |
    +------------------------------------------------+----------------+-----------------+--------------------+---------------+---------------------+
    |switchd IDL batch 3 updates status of ACL event | 10, 20, 30, 40 |  10, 20, 30, 40 |                    |      3        |  3: applied         |
    +------------------------------------------------+----------------+-----------------+--------------------+---------------+---------------------+

```



Port Table - columns to handle a failure to apply an ACL due to insufficient hardware resources:

- aclv4\_in\_applied: represents the current, successfully applied ACL
- aclv4\_in\_cfg: represents the ACL (potentially in flight) desired to be applied
- aclv4\_in\_cfg\_version: represents the version of the ACL in the aclv4\_v4\_cfg column
- aclv4\_in\_status: key/value pairs (see below) associated with the cfg_version of the ACL.


Sequence of applying ACLs to a port, ACL1 and ACL2 successfully, ACL3 failure
```ditaa

    +-------------------------------------------+------------------+--------------+----------------------+-----------------+
    | event                                     | aclv4_in_applied | aclv4_in_cfg | aclv4_in_cfg_version | aclv4_in_status |
    +-------------------------------------------+------------------+--------------+----------------------+-----------------+
    | UI after successful ACL applied           |     ACL 1        |    ACL 1     |           1          |   1: applied    |
    +-------------------------------------------+------------------+--------------+----------------------+-----------------+
    | UI 1 apply ACL 2                          |     ACL 1        |    ACL 2     |           2          |   1: applied    |
    +-------------------------------------------+------------------+--------------+----------------------+-----------------+
    | switchd applies ACL 2 in hw               |     ACL 1        |    ACL 2     |           2          |   2: applied    |
    +-------------------------------------------+------------------+--------------+----------------------+-----------------+
    | switchd updates status of ACL event       |     ACL 2        |    ACL 2     |           2          |   2: applied    |
    +-------------------------------------------+------------------+--------------+----------------------+-----------------+
    | UI 2 apply ACL 3                          |     ACL 2        |    ACL 3     |           3          |   2: applied    |
    +-------------------------------------------+------------------+--------------+----------------------+-----------------+
    | switchd applies ACL 3 in hw: fails        |     ACL 2        |    ACL 3     |           3          |   2: applied    |
    +-------------------------------------------+------------------+--------------+----------------------+-----------------+
    | switchd updates status of ACL event       |     ACL 2        |    ACL 3     |           3          |   3: rejected   |
    +-------------------------------------------+------------------+--------------+----------------------+-----------------+



```





## Participating modules

``` ditaa

                    +----------------+        +---------------+        +-----------------+
                    |                |        |               |        |                 |
                    |  CLI/UI/Mgmt   |        |               |        |                 |
                    |  interface     |        |   ops-intfd   |        | ops-classifierd | <--------+
                    |                |        |               |        |                 |          |
                    |                |        |               |        |                 |          |
                    +--------+-------+        +------+--------+        +---------+-------+          |
                             |                       |                           |                  |
                             |                       |                           |                  |
                             +------------+          |         +-----------------+                  |
                                          |          |         |                                    |
                                          v          v         v                                    |
                                        +-+----------+---------+---+                                |
                                        |                          |                                |
                                        |                          |                                |
                                        |          OVSDB           |                                |
                                        |                          |                                |
                                        |                          |                                |
                                        +------------+-------------+                                |
                                                     ^                                              |
                                                     |                                              |
                                 +-------------------v---------------------+                        |
                                 |                                         |                        |
                                 |            Switch Driver                |                        |
                                 |                                         |                        +
                                 |      +---------------------------+      |                 ACL Logging Packets
                                 |      |                           |      |                        +
                                 |      |       ops-switchd         |      |                        |
                                 |      |                           |      |                        |
                                 |      +---------------------------+      |                        |
                                 |      |                           |      |                        |
                                 |      |  switchd OpenNSL plugin   |      |                        |
                                 |      |                           |      |                        |
                                 |      +----------------+----------+      |                        |
                                 |      |                           |      |                        |
                                 |      |      OpenNSL SDK          |      |                        |
                                 |      |                +----------+      |                        |
                                 |      |                |   CoPP   |      |                        |
                                 |      +----------------+----------+      |                        |
                                 |                                         |                        |
                                 |                                         |                        |
                                 +-------------------+---------------------+                        |
                                                     ^                                              |
                                                     |                                              |
                                 +-------------------v---------------------+                        |
                                 |                                         |                        |
                                 |        OpenNSL            Linux         |                        |
                                 |        Kernel Drivers     Kernel        +------------------------+
                                 |                                         |
                                 +-----------------------------------------+
                                 |                                         |
    traffic on ports +-------->  |            Switch Hardware              | ---------------->  traffic filtered
    with ACLs applied            +-----------------------------------------+                    by ACLs

```

### CLI/UI/Management Interface
Creates ACLs and ACEs, and applies the ACLs to ports.  Interacts with the ACL, ACL_Entry and Port tables in the database.

### CoPP
ACLs will utilize Control Plane Policing (CoPP) within the OpenNSL plugin to limit the number of ACL logging packets copied to the cpu to 5 packets per second.


### ops-intfd
The application of ACLs in hardware will be used to set hw\_ready\_state column in the interface table when ACLs has determined the interface is ready to pass traffic. The ops-intfd daemon will monitor this column to determine if an interface can be set to forward traffic.

ACLs will set the hw\_status in the following situations:


- The hw\_status will be set to blocked at init.  As ACLs are successfully applied in hardware the hw\_status will be set to forward.


- When a port is added to a LAG that has an ACL applied, if there are not enough hardware resources available to accommodate the ACL on the incoming port the hw\_ready\_state will be set to blocked for the associated interface.  The interface will remain blocked until the ACL is unapplied from the LAG.  If enough hardware resources are freed to accommodate the ACL on all interfaces in the LAG, the ACL may be re-applied.



### ops-classifierd
The classifierd daemon will update the hw_ready_state of the associated ports in the interface table that have an ACL applied.

#### ACL Logging

When the 'log' keyword is specified for an ACE, packets that match this entry will be copied to the switch to be logged to the configured system log.  The first packet that matches any log enabled ACE in an ACL will be logged to the system log.  The reception of this packet will also start the ACL logging timer.  Subsequent packets that match log enabled ACEs will not be logged to the system log for the duration of the ACL logging timer.  When the ACL logging timer expires a list of all the ACLs and log enabled ACEs with their corresponding hitcounts will be logged to the system log.  The next packet that matches a log enabled ACE will be logged, repeating the process of starting the ACL logging timer.

To protect the switch from being overwhelmed by ACL logging packets CoPP will be utilized (see above) to rate limit these packets.

The implementation of ACL logging supports logging on 'deny' ACEs only.

The setting of the 'log' keyword in an ACE will automatically set the 'count' keyword in the ACE to enable statistics for the purpose of reporting hitcounts when the logging timer expires.

### ops-switchd
As ACLs are applied to and removed from ports, switchd communicates with hardware to program the ACL on the physical interfaces.  Updates aclv4\_in\_applied, aclv4\_in\_cfg, aclv4\_in\_cfg_version, aclv4\_in\_status columns in the port table.

Updates the aclv4\_in\_statistics column when statistics are periodically requested for a given port, ACL type and direction.

ACLs may be modified while the ACL is applied to ports.  Switchd will monitor the ACL table's cfg_aces columns and update the in\_progress\_aces

The ACL feature plugin will listen to the port table for port row modification events and unapply the ACL from the physical interfaces in hw as part of bridge\_reconfigure loop in switchd.



## OVSDB-Schema
``` ditaa

     ACL Table
     +----------+-----------+-----------------+-----------------+----------+--------------+-----------------+---------------------+
     |   name   | list_type |     cur_aces    |    cfg_aces     | status   | cfg_version  | in_progress_aces| in_progress_version |
     +----------+-----------+-----------------+-----------------+----------+--------------+-----------------+---------------------+
                            | seqNum/ACE UUID | seqNum/ACE UUID | string   |              | seqNum/ACE UUID |
                            |                 |                 +----------+              |                 |
                            | seqNum/ACE UUID | seqNum/ACE UUID | version  |              | seqNum/ACE UUID |
                            |                 |                 +----------+              |                 |
                            | seqNum/ACE UUID | seqNum/ACE UUID | state    |              | seqNum/ACE UUID |
                            |                 |                 +----------+              |                 |
                            | seqNum/ACE UUID | seqNum/ACE UUID | code     |              | seqNum/ACE UUID |
                            |                 |                 +----------+              |                 |
                            | seqNum/ACE UUID | seqNum/ACE UUID | message  |              | seqNum/ACE UUID |
                            |                 |                 +----------+              |                 |
                            | seqNum/ACE UUID | seqNum/ACE UUID |                         | seqNum/ACE UUID |
                            |                 |                 +                         |                 |
                            | seqNum/ACE UUID | seqNum/ACE UUID |                         | seqNum/ACE UUID |
                            |      ...        |      ...        +                         |       ...       |
                            | max 512 entries | max 512 entries |                         | max 512 entries |
                            +-----------------+-----------------+                         +-----------------+


    ACE Table
    +---------+--------+--------+--------+----------+-----------------+---------------------------+-----------------+-----------------+---------------------------+-----+-------+
    | comment | action | src_ip | dst_ip | protocol | src_l4_port_min | src_l4_port_range_reverse | dst_l4_port_min | dst_l4_port_max | dst_l4_port_range_reverse | log | count |
    +---------+--------+--------+--------+----------+-----------------+---------------------------+-----------------+-----------------+---------------------------+-----+-------+


    Port Table
    +------------------+--------------+----------------------+-----------------+---------------------+
    | aclv4_in_applied | aclv4_in_cfg | aclv4_in_cfg_version | aclv4_in_status | aclv4_in_statistics |
    +------------------+--------------+----------------------+-----------------+---------------------+
                                                             | version         | seqNum/hitcounts    |
                                                             +-----------------+                     |
                                                             | state           | seqNum/hitcounts    |
                                                             +-----------------+                     |
                                                             | code            | seqNum/hitcounts    |
                                                             +-----------------+                     |
                                                             | message         | seqNum/hitcounts    |
                                                             +-----------------+                     |
                                                                               | seqNum/hitcounts    |
                                                                               |                     |
                                                                               | seqNum/hitcounts    |
                                                                               |      ...            |
                                                                               | max 512 entries     |
                                                                               +---------------------+

```
### ACL Table
The list of Access Control Lists (ACLs) in the system.  A list need not be applied to be in this table.  A list is identified by name and type.  Names must be unique within a type, but are not required to be unique within the system.

There is a one to many relationship between ACLs and Access Control Entries (ACEs).  The columns *cur\_aces*, *cfg\_aces* and *in\_progress\_aces* are key/value pairs.  The key is the sequence number of the ACL and the value is the uuid of the ACE in the *ACL\_Entry* table.


#### name
The name of the ACL.  A string, up to 64 characters long.

#### list_type
The type of the list.  Current support is for IPv4 address families.  Future support will extend to IPv6 and MAC list types.

#### cur\_aces
The currently configured version of the ACL.  Access Control Entries (ACE) specified in this column are defined in the "ACL_Entry" table and prioritized within the ACL by the sequence number of the ACE.  This ACL may or may not be applied.

This column is written by switchd.

#### cfg\_aces
The desired version of the ACL.  ACEs specified in this column are defined in the "ACL_Entry" table and prioritized within the ACL by the sequence number of the ACE.  This ACL may or may not be applied.

This column is written by the management interface.

#### in\_progress\_aces
The in flight version of the ACL.  ACEs specified in this column are defined in the "ACL_Entry" table and prioritized within the ACL by the sequence number of the ACE.  This ACL may or may not be applied.

Updates to an ACL may fail if an ACL is applied utilizing resources in hardware.  As ACEs are added to an applied ACL, there may not be enough hardware resources to accommodate the ACL modification.  In this situation switchd will return an error.  If the modification is successful the list of ACEs in this column will be copied into the "cur_aces" column.

This column is written by classifierd.

#### cfg\_version
The version of the ACL in the cfg\_aces column.

This column is written by the management interface.

#### in\_progress\_version
The version of the ACL that is currently being processed in the in\_progress\_aces column.

This column is written by the classifierd

#### status
Key/value pairs containing the following status information pertaining to the cfg\_aces column.

These values are written by switchd.

- status\_string: The status of the last version of the cfg\_aces that has been processed by
 switchd.  Accepted values are: in\_progress, applied, rejected and canceled.
- version: The version of cfg\_aces that corresponds to this status
- state: Valid values are in\_progress, applied, rejected and canceled.
- code: Numeric error.  This value is expected to be 0 when the state value is applied.
- message: Detailed reason for the code.  This value is expected to be empty when the state value is applied.


### ACL\_Entry Table
This table contains the individual entries (Access Control Entries ACEs) that comprise an ACL.  Each ACE is identified by a sequence number in the ACL table.

#### comment
A descriptive string associated with the specified ACE.
This is an optional parameter.

#### action
Action to take when a packet matches this entry.  Available actions are *permit* and *deny*.

#### src_ip
The source IPv4 address in the following format:
X.X.X.X/X.X.X.X or *any*

#### dst_ip
The destination IPv4 address in the following format:
X.X.X.X/X.X.X.X or *any*

#### protocol
The IPv4 protocol.

#### src\_l4\_port\_min
Source L4 port to be used as the minimum value, used in conjunction with src\_l4\_port\_max and src\_l4\_port\_range\_reverse to determine the desired source L4 port functionality.

#### src\_l4\_port\_max
Source L4 port to be used as the maximum value, used in conjunction with src\_l4\_port\_min and src\_l4\_port\_range\_reverse to determine the desired source L4 port functionality.

#### src\_l4\_port\_range\_reverse
Specifies if the values in src\_l4\_port\_min and src\_l4\_port\_max should be treated as specifying values not to be matched.

#### dst\_l4\_port\_min
Destination L4 port to be used as the minimum value, used in conjunction with dst\_l4\_port\_max and dst\_l4\_port\_range\_reverse to determine the desired destination L4 port functionality.

#### dst\_l4\_port\_max
Destination L4 port to be used as the maximum value, used in conjunction with dst\_l4\_port\_min and dst\_l4\_port\_range\_reverse to determine the desired destination L4 port functionality.

#### dst\_l4\_port\_range\_reverse
Specifies if the values in dst\_l4\_port\_min and dst\_l4\_port\_max should be treated as specifying values not to be matched.

#### log
Log action: enable ACL logging for packets that match this ACE.
Accepted value: *true*

#### count
Count action: enable hitcounts in hardware for packets that match this ACE.
Accepted value: *true*


### Interface Table
ACLs will set hw\_ready\_state column in the interface table when ACLs has determined the interface is ready to pass traffic.

At init this column will be in a blocked state until ACLs has determined that 1. there is no ACL applied or 2. any ACL applied has been successfully configured in hardware.

When an interface is added to a LAG and the LAG has an ACL applied the ACL applied to the LAG must also be applied to the incoming interface.  If there are not enough hardware resources available to apply the ACL onto the incoming interface ACLs will set the hw\_ready\_state column to blocked.  The user must unapply the ACL, free the needed hardware resources and then re-apply the ACL to the LAG in order for all the interfaces within the LAG to have their hw\_ready\_state columns set to forward.


Please see <ref> for details on the implementation of the Port State Pecking Order.

### Port Table
#### aclv4\_in\_applied
The ACL as referenced in the "ACL" table that has successfully been programmed in hardware on this port.  This value is written by switchd after hardware has been successfully programmed.

#### aclv4\_in\_cfg
The ACL as referenced in the "ACL" table that is desired to be applied.  This list may or may not be successfully applied due to hardware resource limitations.
This value is written by the management interface.

#### aclv4\_in\_cfg\_version
An integer referring to the version of the ACL in the aclv4\_in\_cfg column.  The management interface writes this value and uses it to determine success or failure of the attempted application of the ACL. This value will be incremented by each management interface each time it changes the aclv4\_in\_cfg column.

#### aclv4\_in\_status
Key/value pair written by switchd consisting of the following:

- version: aclv4\_in\_cfg version that this status pertains to

- state: state of this version of the application of the ACL, values may be "applied", "in_progress", "canceled" or "rejected".
- code: Numeric error code, will be '0' when the state is "applied"
- message: Detailed reason for the error state, will be empty when the state is "applied"

#### aclv4\_in\_statistics
Statistics for the ACL applied to this port for ACEs that have the 'count' keyword specified.  Statistics are key/value pairs of the ACE sequence number and an integer representing the statistics for that entry.  Statistics are updated on demand via a CLI command.
This column is updated by switchd.

## References
* [Access List CLI document](http://git.openswitch.net/cgit/openswitch/ops/tree/docs/access_list_cli.md)
* [Port State Pecking Order Design document](http://git.openswitch.net/cgit/openswitch/ops/tree/docs/port_state_pecking_order_design.md)
* [High Level Design of the ops-switchd-opennsl-plugin](http://git.openswitch.net/cgit/openswitch/ops-switchd-container-plugin/tree/DESIGN.md)
* [High Level Design of ops-switchd](http://git.openswitch.net/cgit/openswitch/ops-switchd/tree/DESIGN.md)
