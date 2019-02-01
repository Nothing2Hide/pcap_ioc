#! /usr/bin/env python
import argparse
import code
from .pcap import Pcap
import pyshark


def main():
    parser = argparse.ArgumentParser(description='Process some integers.')
    subparsers = parser.add_subparsers(help='Subcommand')
    parser_a = subparsers.add_parser('ioc', help='Extract IOCs')
    parser_a.add_argument('FILE', help='File')
    parser_a.set_defaults(subcommand='ioc')
    parser_c = subparsers.add_parser('shell', help='Open a shell with scapy')
    parser_c.add_argument('FILE',  help='File')
    parser_c.set_defaults(subcommand='shell')
    args = parser.parse_args()

    if 'subcommand' in args:
        if args.subcommand == 'ioc':
            pcap = Pcap(args.FILE)
            for i in pcap.indicators:
                print('%s - %s' % (i['type'], i['value']))
        elif args.subcommand == 'shell':
            pkts = pyshark.FileCapture(args.FILE)
            code.interact(local=locals())
        else:
            parser.print_help()
    else:
        parser.print_help()
