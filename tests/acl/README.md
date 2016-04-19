




[TOC]


===================
README!
===================
This document lists the pieces that make up a feature test suite.

#### <i class="icon-file"></i> Adding Exceptions
When a commands fails (i.e the shell receives an output in a non-show command), the library will try to determine the failure to raise a typed exception. To do so, it has to know what error the command outputs. For example:

```
switch# configure terminal
switch(config)# configure exc
% Unknown command.
 
```
In the above scenario, we can identify this error using a regular expression that will match the "Unknown command" output. To specify a new typed exception, edit the file tools/vtysh_meta.py and modify the VTYSH_EXCEPTIONS_SPEC dictionary, which maps the name of the new exception to a regular expression for that error. 
```
      (
        'UnknownCommandException',
        [
            'Unknown command', '% Unknown command.'
        ]
    ), (

 
```

#### <i class="icon-file"></i> Adding Commands To Library 
To add a new command to the library, a developer needs to:

1. List item
2.  Find if the context for the command is already defined on the dictionary.
3.  If it is not defined, it has to be added.
4.  Define the new command inside commands on the correct context.
5.  Execute the generator script. To do this:
i.  Go to the topology_lib_vtysh root folder.
ii. Run tox to validate the script and prepare the py34 environment.
iii.Run source .tox/py34/bin/activate.
iv. Run ./tools/updatelib.
v.  Run deactivate.

#### <i class="icon-file"></i> Use Of Scapy Library 
Scapy library functions are defined in: 
https://github.com/HPENetworking/topology_lib_scapy.git.

#### <i class="icon-file"></i> Topology
requirements.txt has details of the working topology.