# IPLookup

IPLookup is a network security tool that allows a user to take a list of IP addresses from a Firewall, IDS, Logs, etc. and determine if there is a risk associated with letting that IP address into your network.

### Tech

IPLookup uses a number of open source projects and tools to work properly:

* [Progress](https://github.com/verigak/progress) - Gives a progress bar to show an ETA
* [Gmplot](https://pypi.python.org/pypi/gmplot/1.0.5) - Allows for the data to be displayed on a Google Map
* [Cymon.IO](https://www.cymon.io) - Open Source Threat Intel
* [IP Tracker](http://www.ip-tracker.org/blacklist-check.php) - Database of blacklisted IP addresses
* [Reputation Authority](http://www.reputationauthority.org/) - Database of reputation of IPs based on past behaviors
* [Alien Vault](https://www.alienvault.com/open-threat-exchange/dashboard) - Database of open threat intel
* [IPinfo.io](http://ipinfo.io/developers) - Location, hosting, ISP, and other types of IP address info

### Installation

Install IPLookup using the following command:

```sh
$ git clone https://github.com/rookford343/IPLookup.git
```

**_In order to run the code you will need to get a Cymon.io API key and hard code it into the main program._**

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
