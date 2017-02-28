#!/usr/bin/env python

""" This tool converts a whitelist using ip addresses in parentheses to a search string to convert it to dns whitelisting """

__author__ = "Nicolas P."
__version__ = "0.0.3"
__status__ = "Alpha"

import argparse
import urllib, urllib2
import re

class ServerClass(object):
    def __init__(self, fl):
        self.apps = {}
        i = 0
        app_name = ''
        for i in range(0, len(fl)):
            if re.search('\[serverClass:[^:]+\]', fl[i]):
                app_name = re.search('\[serverClass:([^:]+)\]', fl[i]).group(1)
                self.apps[app_name] = [i]
            elif re.search('whitelist\.\d+\s*=\s*[\d\.]+', fl[i]):
                lst = re.search('whitelist\.\d+\s*=\s*([^\)]+\))', fl[i]).group(1)
                self.apps[app_name].append(self.recompose_ip(lst))

    def __repr__(self):
        """ Print friendly object representation """
        rep = '\nList of apps in serverclass.conf:\n\n'
        for i in self.apps:
            rep += 'app: %s,  index: %d\n' % (i, self.apps[i][0])
            for a in range(1, len(self.apps[i])):
                rep += '+ Whitelisted: ' + ', '.join(self.apps[i][a])
                rep += '\n'
        return rep

    def recompose_ip(self, wl):
        """ Function takes the line in old format and recompose all IPs """
        ips = []
        r = re.search('([\d\.]+)\(([\d\|]+)\)', wl)
        base = r.group(1)
        items = re.split(r'[|]',r.group(2))
        for i in items:
            ips.append("%s%s" % (base, i))
        return ips


def main():
    parser = argparse.ArgumentParser(description='Splunk serverclass ip converter')
    parser.add_argument('--path', default='serverclass.conf', help='path to serverclass.conf file')
    args = parser.parse_args()

    # Opening file in readonly and object initialisation
    with open(args.path, 'r') as f:
        sc = ServerClass(f.readlines())

    # For sanity check, printing object informations
    print sc

if __name__ == '__main__':
         main()
