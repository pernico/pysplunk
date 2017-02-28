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
        n = 1
        app_name = ''
        for i in range(0, len(fl)):
            if re.search('\[serverClass:[^:]+\]', fl[i]):
                app_name = re.search('\[serverClass:([^:]+)\]', fl[i]).group(1)
                self.apps[app_name] = [n]
                n = n + 1
            elif re.search('whitelist\.\d+\s*=\s*[\d\.]+', fl[i]):
                lst = re.search('whitelist\.\d+\s*=\s*([^\)]+\))', fl[i]).group(1)
                self.apps[app_name].append(self.recompose_ip(lst))

    def __repr__(self):
        """ Print friendly object representation """
        rep = '\nList of apps in serverclass.conf:\n\n'
        for i in self.apps:
            rep += '%s\n' % (i)
            for a in range(1, len(self.apps[i])):
                rep += '  ' + ', '.join(self.apps[i][a])
            rep += '\n'
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

    def get_ips_ored(self, app_name):
        """ Returns list containing all IPs associated to the app in a preformatted fashion for Splunk """
        lst =''
        for i in range(1,len(self.apps[app_name])):
            lst += ' OR '.join(self.apps[app_name][i])
        return lst


def main():
    parser = argparse.ArgumentParser(description='Splunk serverclass ip converter')
    parser.add_argument('--path', default='serverclass.conf', help='path to serverclass.conf file')
    args = parser.parse_args()

    # Opening file in readonly and object initialisation
    with open(args.path, 'r') as f:
        sc = ServerClass(f.readlines())

    # For sanity check, printing object informations
    print sc

    answer = raw_input("Please indicate for which app you'd like the IPs: ")

    print '+'*50 + '\n'
    splunk_search = """earliest=-1h@h index =_internal sourcetype="splunkd_access" method="POST" "/services/broker/phoneHome/" ("""
    splunk_search += sc.get_ips_ored(answer)
    splunk_search += ") | stats sparkline count by src_clientname clientip src_dns src_hostname"
    print splunk_search
    print '\n' + '+'*50 + '\n'

if __name__ == '__main__':
         main()
