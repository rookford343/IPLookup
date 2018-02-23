#!/usr/bin/python

import os
import datetime
import requests
import csv
import time
import random
from argparse import ArgumentParser
from iso_country_codes import COUNTRY_NAME
try:
    from netaddr import *
except ImportError as e:
    print '[!] Warning! You do not have a dependency installed for netaddr'
    print '[!] Run `pip install netaddr` and rerun program'
    exit(1)
try:
    from Rook_lib.progress.bar import *
except ImportError as e:
    print '[!] Warning! You do not have a dependency installed for showing the progress bar.'
    exit(1)
try:
    from Rook_lib.gmplot import *
except ImportError as e:
    print '[!] Warning! You do not have a dependency installed for gmplot.'
    exit(1)

PROGRAM = 'IP_Info'
VERSION = '1.0'
AUTHOR = 'Daniel Ford'
lat = []
lng = []
label = []

def GetIPs(file, c):
    ips = []
    if(file.endswith(".csv")):
        with open(file, 'rU') as csvfile:
            reader = csv.reader(csvfile, delimiter=',', quotechar='\"')
            header = False
            for row in reader:
                if header:
                    header = False
                    continue
                try:
                    ips.append(row[c])
                except IndexError as e:
                    print '[-] Error parsing the IP from the following line:\n\t%s' % row
    else:
        with open(file, 'r') as textfile:
            for line in textfile:
                try:
                    ips.append(line.strip())
                except IndexError as e:
                    print '[-] Error parsing the IP from the following line:\n\t%s' % line
    return ips

def analyzeIPs(ips, output):
    count_analyzed = 0
    count_not_analyzed = 0
    global lat
    global lng
    global label
    if Bar and not output == 'SingleIP':
        bar = Bar('Analyzing', max=len(ips), suffix='%(index)d/%(max)d - Elapsed: %(elapsed_td)s - Remaining: %(eta_td)s')
    elif output == 'SingleIP':
        print '[*] Analyzing IP Address: %s' % ips[0]
    if len(ips) > 1:
        csvfile = open(output, 'wb')
        writer = csv.writer(csvfile, delimiter=',', quotechar='\"')
        writer.writerow(['IP', 'Country', 'Region', 'City', 'Hostname', 'ISP', 'Latitude/Longitude', 'Location URL'])
    if not output == "SingleIP":
        bar.start()
    for i in ips:
        # Get Location Info
        where = []
        loc_url = 'https://ipinfo.io/%s/' % i
        while True:
            try:
                info = requests.get(loc_url)
                break
            except requests.exceptions.HTTPError as errh:
                print ("\nHTTP Error:",errh)
            except requests.exceptions.ConnectionError as errc:
                print ("\nError Connecting:",errc)
            except requests.exceptions.Timeout:
                print ("\nTimeout Error:",errt)
            except requests.exceptions.RequestException as err:
                print ("\nOops: Something went wrong",err)
        if info.status_code == 404:
            print "\n[!] %s is not a valid IP address!" % i
            print "[*] Moving to next IP..."
            count_not_analyzed += 1
            bar.next()
            continue
        elif info.status_code == 429:
            print "\n[!] You have been rate limited by ipinfo.io!"
            print "[!] Exiting Progam..."
            exit(1)
        ipinfo = info.json()
        try:
            country = ipinfo["country"]
            country = COUNTRY_NAME[country]
            where.append(country)
        except:
            print "\n[!] No info for %s! Could be a private IP!" % i
            if output == "SingleIP":
                print '[!] Ending program...'
                exit(0)
            print "[*] Moving to next IP..."
            count_not_analyzed += 1
            bar.next()
            continue
        try:
            region = ipinfo["region"]
            region = "".join([x for x in region if ord(x) < 128])
            where.append(region)
        except:
            region = ""
            region = "".join([x for x in region if ord(x) < 128])
            where.append(region)
        try:
            city = ipinfo["city"]
            city = "".join([x for x in city if ord(x) < 128])
            where.append(city)
        except:
            city = ""
            city = "".join([x for x in city if ord(x) < 128])
            where.append(city)
        try:
            hostname = ipinfo["hostname"]
            hostname = "".join([x for x in hostname if ord(x) < 128])
        except:
            hostname = "Not Found"
            hostname = "".join([x for x in hostname if ord(x) < 128])
        try:
            isp = ipinfo["org"]
            isp = "".join([x for x in isp if ord(x) < 128])
        except:
            isp = "Not Found"
            isp = "".join([x for x in isp if ord(x) < 128])
        try:
            loc = ipinfo["loc"]
        except:
            loc = ""
        where = ", ".join([x for x in where if x])

        if output == "SingleIP":
            # Print out results
            print '[+] Analysis Done!'
            print '\n[*] Location:\t\t%s' % where
            print '[*] Hostname:\t\t%s' % hostname
            print '[*] ISP:\t\t%s' % isp
            print '[*] Location:\t\t%s' % loc
            print '\n[+] Links:'
            print '[*] IP Info URL:\t%s' % loc_url
            exit(0)
        else:
            # Move marker so they don't stack
            tmp_lat = loc.split(",")[0]
            tmp_lng = loc.split(",")[1]
            if not region or not city:
                pass
            elif not ipinfo["region"] and not ipinfo["city"]:
                tmp_lat = float(tmp_lat) + random.uniform(0.0000,0.0999)
                tmp_lng = float(tmp_lng) + random.uniform(0.0000,0.0999)
                tmp_lat = str(tmp_lat)
                tmp_lng = str(tmp_lng)
            elif ipinfo["region"] and not ipinfo["city"]:
                tmp_lat = float(tmp_lat) + random.uniform(0.0000,0.0099)
                tmp_lng = float(tmp_lng) + random.uniform(0.0000,0.0099)
                tmp_lat = str(tmp_lat)
                tmp_lng = str(tmp_lng)
            elif ipinfo["region"] and ipinfo["city"]:
                tmp_lat = float(tmp_lat) + random.uniform(0.0000,0.0009)
                tmp_lng = float(tmp_lng) + random.uniform(0.0000,0.0009)
                tmp_lat = str(tmp_lat)
                tmp_lng = str(tmp_lng)

            # Splits the Location data into Latitude and Longitude
            lat.append(tmp_lat)
            lng.append(tmp_lng)

            # Create labels
            label.append("<h1>%s</h1><small>%s</small>" % (i,where))

        writer.writerow([i,country,region,city,hostname,isp,loc,loc_url])
        count_analyzed += 1
        bar.next()
    bar.finish()
    return [len(ips),count_analyzed, count_not_analyzed]

def createMap(lat, lng, map_loc):
    gmap = gmplot.GoogleMapPlotter(21.9452245, -1.0986107, 3)
    for i in range(0, len(lat)-1):
        gmap.marker(float(lat[i]), float(lng[i]), 'red', label=label[i])
        gmap.circle(float(lat[i]), float(lng[i]), 500, 'red', ew=2)
        gmap.draw(map_loc)

    # Save map as a complete HTM file

if __name__ == '__main__':
    c = ArgumentParser(description='%s: analyzes an IP or a list of IPs and determines risk associated with those IPs.' % PROGRAM, version=VERSION, epilog='Developed by ' + AUTHOR + ' as an open source tool.')
    c.add_argument('-i', help='input file', required=True)
    c.add_argument('-o', help='output CSV file', required=False)
    c.add_argument('-m', help='Creates a map to view the information on it', required=False, action='store_true')
    c.add_argument('--ip_column', help='coulmn in the CSV file with the ips (starting with 0)', required=False)

    args = c.parse_args()

    if '.csv' in args.i or '.txt' in args.i:
        if not os.path.exists(args.i):
            print '[-] Error! Can not find the input file'
            exit(1)
        if args.o:
            if os.path.exists(args.o):
                print '[!] Warning! Output file exists and will be overwritten'
                cont = raw_input('[?] Continue? (Y/n) ')
                if cont.lower() in ['n', 'no']:
                    print 'Exiting program...'
                    exit(1)
            ip_column = 0
            if args.ip_column:
                try:
                    ip_column = int(ip_column) - 1
                except ValueError as e:
                    print '[-] Error! Invalid column number'
                    exit(1)
            print '[*] Parsing IP values from: %s' % args.i
            ips = GetIPs(args.i, ip_column)
            start_time = datetime.datetime.now()
            if len(ips) > 1000:
                print "[!] Will not be able to run all IPs in a day! Rate limit issues..."
                cont = raw_input('[?] Continue? (Y/n) ')
                if cont.lower() in ['n', 'no']:
                    print 'Exiting program...'
                    exit(1)
            print '[*] Analyzing %d IPs...' % len(ips)
            results = analyzeIPs(ips, args.o)
            print '\n[+] Analysis complete. CSV output saved to: %s' % args.o
            if args.m:
                print '\n[*] Creating map with location data...'
                map_loc = args.o[:args.o.rfind(".")] + ".html"
                createMap(lat,lng,map_loc)
                print '[+] Map complete. Map saved to: %s' % map_loc
            end_time = datetime.datetime.now()
            run_time = end_time - start_time
            print '\n[*] IPs provided:\t%d' % results[0]
            print '[*] IPs analyzed:\t%d' % results[1]
            print '[*] IPs NOT analyzed:\t%d' % results[2]
            print '[*] Total runtime:\t%s' % str(run_time)[:-5]
        else:
            print '[!] Error! Need to supply an output CSV file!'
            exit(1)
    else:
        if args.o:
            print '[!] Warning! Will not save output for single IP!'
        try:
            ip = IPAddress(args.i)
            analyzeIPs([args.i],"SingleIP")
        except ValueError as e:
            print '[!] Invalid input type! Please only input a single IP, CSV file, or Text File!'
