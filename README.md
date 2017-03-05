# asa-parser
Cisco ASA log parser - makes searching ASA syslog messages easier.

## Usage
```
usage: asa-parser.py [-h] [--sourceinterface SOURCEINTERFACE]
                     [--sourceip SOURCEIP] [--sourceport SOURCEPORT]
                     [--destinterface DESTINTERFACE] [--destip DESTIP]
                     [--destport DESTPORT] [--proto PROTO] [--policy POLICY]

optional arguments:
  -h, --help            show this help message and exit
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
```
