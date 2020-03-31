# REPCAP
A Command line tool for quickly rewriting packet captures and replaying them.

# Current Files
requirements.txt - list of Python modules required - Currently only requirment is Scapy - https://scapy.net/
repcap.py - main file - application itself
README.md - this file

# Command Line Tool that takes in arguments
Current version supports 5 modes: passed to tool via -m command
0 - the ability to identify IP and MAC addresses in a packet capture - default when no mode provided
1 - the ability to replay a packet capture unaltered - must include interface to send it via -i argument
2 - the ability to read in a packet capture and rewrite the IP and MAC Addresses and create a new packet capture file (.pcap)
3 - the ability to read and rewrite ( same as 2 ) and then replay the capture ( with interface provided via -i argument )
4 - a walk through to create a configuration file that will be used by modes 1 - 3 - Can finish with packet rewrite ( mode 2 )

# Current Version 1.0 - initial release


Input File must be a .pcap or .pcapng file

# Arguments:
-m  mode  Will take 1 - 4 ( 0 implied when no mode provided )
-i  target interface - used for packet replay - provide name of interface ie en1
-c  configuration file - if not provided will look for default which is based on name of provided pcap <name of sourcefile>.config - if provide example.pcap will look for example.config if not provided via -c
-o  output file - if not provided will use name of <name of sourcefile>new.pcap - if provide example.pcap will use / create examplenew.pcap

example: repcap.py example1.pcap - will list unique ip and mac addresses in example1.pcap

example: repcap.py -m 1 -i en0 example1.pcap - will replay example1.pcap unaltered out interface en0

example: repcap.py -m 4 example1.pcap - will guide through creating a config file and output example1.config and optionally example1new.pcap when rewriting
