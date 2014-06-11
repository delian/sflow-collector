sflow-collector
===============

This is a demo Sflow collector example made with my Node.JS node-sflow module.

It expects the SFlow agent to send raw Ethernet packets over SFlow (as you could get by default Extreme switches) and it measures how many packets match a destination ip address for a sample time. If the pps goes above defined threshold, it will execute an external application and another one in minTimeout interval. If the traffic continue being above the pps, it will execute again the application, but this time for a larger period, and so on, and so on.

This example has been here to show you how to use SFlow and the node-sflow module.
The supposed usage of this code is to allow you to block a traffic going to a certain IP address if it goes above a certain threshold.
The code does not block the traffic, it just execute an external application that has to block it and another one that has to unblock it.

The configuration file contains a list of rules that could match vlan and ip addresses. The rule is executed if a packet match both the VLAN list and the ip addresses. If the vlan list is not present, it will match all vlans. If the networks list is not present, it will match all the networks.
The rules are executed in the configured order within the array.
This way you can easily create overlapping rules and with them white and black lists.

Generally this code should provide you an example and idea how to auto block traffic to certain ip address in case of flood or incorrect usage.
For example you can easily implement export of BGP community to this ip address which will route it to Null in your upstream internet providers.
This way you can automate the filtering.

NOTE: THIS IS JUST AN EXAMPLE! Read and learn! It is not considered to be used in production unless you know what are you doing!
