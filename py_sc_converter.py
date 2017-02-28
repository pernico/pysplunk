#!/usr/bin/env python

""" This tool converts a whitelist using ip addresses in parentheses to a search string to convert it to dns whitelisting """

__author__ = "Nicolas Perreault"
__version__ = "0.0.2"
__status__ = "Alpha"

import argparse
import urllib, urllib2
from xml.dom import minidom
import re

parser = argparse.ArgumentParser(description='Splunk serverclass ip converter')
parser.add_argument('whitelist', help='This contains the whitelist to convert')
args = parser.parse_args()

r = re.search("(whitelist\.\d+ = )?([\d\.]+)\(([0-9\.|]+)\)", args.whitelist)
base = r.group(2)
items = re.split(r'[|]',r.group(3))

recherche = """earliest=-1h@h index =_internal sourcetype="splunkd_access" method="POST" "/services/broker/phoneHome/" ("""
for b in items[:-1]:
  recherche += "clientip=%s%s OR " % (base, b)
recherche += "clientip=%s%s) | stats sparkline count by src_clientname clientip src_dns src_hostname" % (base, b)

print recherche
