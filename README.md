# pcap-ioc

Python tool to extract potential IOCs from a pcap file using [pyshark](https://kiminewt.github.io/pyshark/)

List of IOCs extracted :

* IP addresses from IP packets
* Domains and IP addresses from DNS requests
* Domains, url and user-agents from HTTP requests
* Domains from HTTPs X509 certificates

To install it, you can just do `pip install pcap_ioc` or install it from this repository with `pip install .`.

## Usage

### As a library

```python
from pcap_ioc import Pcap

p = Pcap('FILE.pcap')
for i in p.indicators:
    print(i)
```

### CLI tool

```
$ pcap_ioc
usage: pcap_ioc [-h] {ioc,misp,shell} ...

Process some pcaps.

positional arguments:
  {ioc,misp,shell}  Subcommand
    ioc             Extract IOCs
    misp            Extract IOCs and search in MISP
    shell           Open a shell with pyshark

optional arguments:
  -h, --help        show this help message and exit
```

To query MISP servers, you need to create a file `~/.misp` with one entry for every MISP server for instance :
```
[server1]
url: https://misp1.example.org/
key: KEYHERE
default: true

[server2]
url: https://misp2.example.org/
key: KEYHERE
```

Then you can query one of these server with `pcap_ioc misp -s misp2 file.pcap`

## License

This software is released under the MIT license.
