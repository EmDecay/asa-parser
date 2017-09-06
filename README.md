# asa-parser
Cisco ASA log parser - makes searching ASA syslog messages easier.  Can search for ACL deny messages or allows based on 'built' messages, and only TCP and UDP (not ICMP or other packet types).  More support will be added time permitting.

## Usage
```
usage: asa-parser.py [-h] [--file FILE] [--sourceinterface SOURCEINTERFACE]
                     [--sourceip SOURCEIP] [--sourceport SOURCEPORT]
                     [--destinterface DESTINTERFACE] [--destip DESTIP]
                     [--destport DESTPORT] [--proto PROTO] [--policy POLICY]
                     [--action ACTION]

optional arguments:
  -h, --help            show this help message and exit
  --file FILE           Log File to Search (default: messages)
  --sourceinterface SOURCEINTERFACE
                        Source Interface (default: any)
  --sourceip SOURCEIP   Source IP (default: any)
  --sourceport SOURCEPORT
                        Source Port (default: any)
  --destinterface DESTINTERFACE
                        Destination Interface (default: any)
  --destip DESTIP       Destination IP (default: any)
  --destport DESTPORT   Destination Port (default: any)
  --proto PROTO         Protocol [tcp|udp] (default: any)
  --policy POLICY       Firewall Policy (default: any)
  --action ACTION       Action [deny|allow] (default: deny)
```
