# CP3cap
A simple "connection oriented packet" sniffer.
Breaks packets down into a connection between a remote and local host for
    easy real time traffic analysis and debugging.

CP3cap is published for free under the terms of the MIT opensource license.

Requires >= C++ 11 std, libpcap and ncurses, uses bsd sockets for pkt nfo

This program attempts to provide a ss / netstat style tool using libpcap
    instead of reading system socket information, plus user interaction.
The goal is to show any "connections" caught by the interface regardless
    of socket logic which causes limitations in the aformentioned tools,
    without showing packet by packet info as many sniffers do. pkt by
    pkt view is good for post analysis, but quickly becomes hard to use
    for monitoring live connections in most situations.
This tool is usefull for any sys-admins, net-admins, and or power users.
    Anybody who wants a simple live overview of any connections going in or
    out of a machine.

CP3cap only cares about ipv4 tcp and udp packets but can easily support
    more protocols. Currently only supports ethernet speaking interfaces
    such as ethernet ports, wireless cards, and the loopback interface.
CP3cap is protocol dumb: it defines a "connection" as a group of packets
    between a local and remote host, sent by either one to the other, on a
    specific protocol set on a specific set of ports. It is not aware of
    things like handshakes, flags, or sessions.
CP3cap will always place a recognized private address (class A | B | C and lo)
    as the local address of a connection, otherwise the local address will
    be the sender address of the first packet observed in a connection.
CP3cap is not designed to handle packet floods or purposefully malformed
    packets, so sniff malicious traffic at your own risk. < duh

CP3cap tries to merge C++ Object Oriented style with C Procedural style
    inorder to use libpcap (which is written in C) so the code can be a bit
    messy. CP3cap uses an infinite pcap_loop() so that all packets are
    captured and processed as quickly as possible untill the user exits.
The use of pcap_loop() makes clean nonblocking ui seperation and OOP difficult
    so suggestions on cleaning up the C++ side (specifically the capture
    engine) and the multi-threading are more than welcome. Eventually I will
    probably do a full rewrite rather than bother with refactoring.

This project is built with portabillity in mind, so beyond the sockets api
    all code should work within the C++ 11 std, libpcap and ncurses.
For example in a windows port all that would change is the sockets api
    (winsocks instead of bsd scokets) and libpcap (preferably would use
    Npcap, but WinPcap if must). which should require almost no code change
    beyond the specific header includes and function names used.
