#! /usr/bin/env python
import os
import sys
import argparse
import code
import configparser
from .pcap import Pcap
from pymisp import PyMISP
import pyshark


def parse_config():
    """Parse configuration file, returns a list of servers"""
    config = configparser.ConfigParser()
    config.read(os.path.join(os.path.expanduser("~"), ".misp"))
    servers = {}
    for s in config.sections():
        try:
            info = {
                    'url': config.get(s, 'url'),
                    'key': config.get(s, 'key')
            }
            servers[s.lower()] = info
            if config.get(s, 'default').lower() == 'true':
                servers['default'] = info
        except configparser.NoOptionError:
            pass
    return servers


def main():
    parser = argparse.ArgumentParser(description='Process some pcaps.')
    subparsers = parser.add_subparsers(help='Subcommand')
    parser_a = subparsers.add_parser('ioc', help='Extract IOCs')
    parser_a.add_argument('FILE', help='File')
    parser_a.set_defaults(subcommand='ioc')
    parser_b = subparsers.add_parser(
            'misp',
            help='Extract IOCs and search in MISP'
    )
    parser_b.add_argument('FILE',  help='File')
    parser_b.add_argument(
            '--verbose',
            '-v',
            action='store_true',
            help='Verbose'
    )
    parser_b.add_argument(
            '--server',
            '-s',
            help='Select MISP server',
            default='default'
    )
    parser_b.set_defaults(subcommand='misp')
    parser_c = subparsers.add_parser('shell', help='Open a shell with pyshark')
    parser_c.add_argument('FILE',  help='File')
    parser_c.set_defaults(subcommand='shell')
    args = parser.parse_args()

    if 'subcommand' in args:
        if args.subcommand == 'ioc':
            pcap = Pcap(args.FILE)
            for i in pcap.indicators:
                print('%s - %s' % (i['type'], i['value']))
        elif args.subcommand == 'misp':
            # Parse MISP config
            conf = parse_config()
            if args.server not in conf:
                print('Invalid MISP server')
                sys.exit(1)
            server = PyMISP(
                    conf[args.server]['url'],
                    conf[args.server]['key'],
                    True,
                    'json'
            )
            pcap = Pcap(args.FILE)
            print("Analyzing pcap")
            for i in pcap.indicators:
                if args.verbose:
                    print('Checking %s' % i['value'])
                events = server.search(values=[i['value']])
                if len(events['response']) > 0:
                    print('Malicious event found for %s' % i['value'])
                    for event in events['response']:
                        print('-%s - %s' % (
                            event['Event']['id'],
                            event['Event']['info']
                        ))
        elif args.subcommand == 'shell':
            pkts = pyshark.FileCapture(args.FILE)
            code.interact(local=locals())
        else:
            parser.print_help()
    else:
        parser.print_help()
