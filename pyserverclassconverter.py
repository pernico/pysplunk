#!/usr/bin/env python

import argparse
import re

parser = argparse.ArgumentParser(description='Splunk serverclass ip converter')
parser.add_argument('whitelist', help='This contains the whitelist to convert')
args = parser.parse_args()

#s = '10.23.100.(1|25|37|254)'
s = args.whitelist
recherche = []

i = s.find('(')
base = s[:i]

items = re.split(r'[|]',s[i+1:-1])

recherche = """earliest=-1h@h index =_internal sourcetype="splunkd_access" method="POST" "/services/broker/phoneHome/ ("""
for b in items[:-1]:
  recherche += "clientip=%s%s OR " % (base, b)
recherche += "clientip=%s%s) | stats sparkline count by src_clientname clientip src_dns src_hostname" % (base, b)

print recherche
