firewatch
=======

Dynamic quota management for nftables. 

This program sets up and manages an external netfilter table (default name netquotas) using libnft which watches for trigger devices.

Trigger rules are added to the netquotas table and are returned back to the program which monitors for events.
Once an event is received, an internal trigger device table is queried and then an appropriate quota is configuredo on each host for that user by adding relevant netfilter rules to the netquotas table.

If the particular trigger device is not seen after a certain period of time, then the rules expire.

Finally, a timer is installed which resets the quotas at a certain time of day.

A config ini file is used to manage the configuration of the trigger devices.

# Purpose

This software was used as a learning experience for a few projects.
1. Its got a nice library for minimal AF_NETLINK exposure to get to grids with using AF_NETLINK in production.
2. To figure out a nice way to tie netfilter to location (the trigger devices can act as a geofence).

The main use of this project was to allow a summer camp to limit kids access to the internet (data cell coverage was poor).
 

Requirements
------------

firewatch runs on Linux (probably greater than 3.1) and requires netfilter with connection tracking enabled.
firewatch uses libev as an event library for both the timers and netfilter queue signalling. Additinal requirements are libmnl and libnftnl.
firewatch needs **cap_net_admin** capabilities on the binary to properly function.

# Implementation

firewatch internally uses netfilter queues to analyze the traffic and make a internal quota lookup based on the trigger hit.

# Performance

firewatch only cares about the trigger devices at runtime. In fact, most of the code revolves around the initial configuration and management of the initial state of the netquotas table. Once the netquotas state is syncronized, the trigger events are typically few and far between and quite trivial.
