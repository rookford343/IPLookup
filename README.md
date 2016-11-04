# IPLookup

IPLookup is a network security tool that allows a user to take a list of IP addresses from a Firewall, IDS, Logs, etc. and determine if their is a risk associated with letting that IP address into your network.

### Tech

IPLookup uses a number of open source projects and tools to work properly:

* [Progress](https://github.com/verigak/progress)
* [Gmplot](https://pypi.python.org/pypi/gmplot/1.0.5)
* [Cymon.IO](https://www.cymon.io)
* [IPVoid](http://www.ipvoid.com/)
* [Project Tor Status](https://torstatus.blutmagie.de/tor_exit_query.php)
* [Reputation Authority](http://www.reputationauthority.org/)
* [IPinfo.io](http://ipinfo.io/developers)

### Installation

Install IPLookup using the following command:

```sh
$ git clone https://github.com/rookford343/IPLookup.git
```

#### Running Code
For a help menu:
```
$ python IPLookup.py -h
usage: IPLookup.py [-h] [-v] -i INPUT [-o OUTPUT] [-m] [--ip_column IP_COLUMN]
IPLookup: analyzes an IP or a list of IPs and determines risk associated with those IPs.
optional arguments:
    -h, --help              show this help message and exit
    -v, --version           show program's version number and exit
    -i INPUT                input file
    -o OUTPUT               output CSV file
    -m                      Creates a map to view the information on it
    --ip_column IP_COLUMN   column in the input CSV file with the IP addresses (starts with 0)

Developed by Daniel Ford as an open source tool.
```
