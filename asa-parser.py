#!/usr/bin/python
# asa-parser.py - Main code for the ASA Parser application
# Author - Matt (emdecay (at) protonmail.com)

import re, csv, argparse

_args = argparse.ArgumentParser()
_args.add_argument("--file", default="messages", required=False, help="Log File to Search (default: %(default)s)")
_args.add_argument("--sourceinterface", default="any", required=False, help="Source Interface (default: %(default)s)")
_args.add_argument("--sourceip", default="any", required=False, help="Source IP (default: %(default)s)")
_args.add_argument("--sourceport", default="any", required=False, help="Source Port (default: %(default)s)")
_args.add_argument("--destinterface", default="any", required=False, help="Destination Interface (default: %(default)s)")
_args.add_argument("--destip", default="any", required=False, help="Destination IP (default: %(default)s)")
_args.add_argument("--destport", default="any", required=False, help="Destination Port (default: %(default)s)")
_args.add_argument("--proto", default="any", required=False, help="Protocol [tcp|udp] (default: %(default)s)")
_args.add_argument("--policy", default="any", required=False, help="Firewall Policy (default: %(default)s)")
_args.add_argument("--action", default="deny", required=False, help="Action [deny|allow] (default: %(default)s)")
args = _args.parse_args()

if (args.action == "deny"):
    p = re.compile('(.*\d\d\:\d\d\:\d\d).*Deny (tcp|udp) src (.*?):(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,5}) dst (.*?):(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,5}) by access-group \"(.*?)\"')
elif (args.action == "allow"):
    p = re.compile('(.*\d\d\:\d\d\:\d\d).*Built (inbound|outbound) (UDP|TCP) connection.*for (.*?):(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,5}).*to (.*?):(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,5}).*')
else:
    print 'Invalid action specified: ' + args.action
    quit()

with open("results.csv", 'wb') as outfile:
    csv_writer = csv.writer(outfile)
    csv_writer.writerow(["Date", "Source Interface", "Source IP", "Source Port", "Destination Interface", "Destination IP", "Destination Port", "Protocol", "Firewall Policy"])
    with open(args.file, 'r') as file:
      for line in file:
        try:
            if (args.action == "deny"):
                results = p.search(line)
                date = results.group(1).strip()
                proto = results.group(2).strip()
                sourceinterface = results.group(3).strip()
                sourceip = results.group(4).strip()
                sourceport = results.group(5).strip()
                destinterface = results.group(6).strip()
                destip = results.group(7).strip()
                destport = results.group(8).strip()
                policy = results.group(9).strip()
            elif (args.action == "allow"):
                results = p.search(line)
                date = results.group(1).strip()
                direction = results.group(2).strip()
                proto = results.group(3).strip()
                if direction == "inbound":
                    sourceinterface = results.group(4).strip()
                    sourceip = results.group(5).strip()
                    sourceport = results.group(6).strip()
                    destinterface = results.group(7).strip()
                    destip = results.group(8).strip()
                    destport = results.group(9).strip()
                else:
                    destinterface = results.group(4).strip()
                    destip = results.group(5).strip()
                    destport = results.group(6).strip()
                    sourceinterface = results.group(7).strip()
                    sourceip = results.group(8).strip()
                    sourceport = results.group(9).strip()
                policy = ""
        except:
          continue
        match = True
        if (args.sourceip != "any") and (args.sourceip != sourceip):
            match = False
        if (args.sourceport != "any") and (args.sourceport != sourceport):
            match = False
        if (args.destip != "any") and (args.destip != destip):
            match = False
        if (args.destport != "any") and (args.destport != destport):
            match = False
        if (args.proto != "any") and (args.proto != proto):
            match = False
        if (args.policy != "any") and (args.policy != policy):
            match = False
        if (args.sourceinterface != "any") and (args.sourceinterface != sourceinterface):
            match = False
        if (args.destinterface != "any") and (args.destinterface != destinterface):
            match = False
        if match == True:
            csv_writer.writerow([date, sourceinterface, sourceip, sourceport, destinterface, destip, destport, proto, policy])
print 'Done.'
