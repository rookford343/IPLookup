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
    from progress.bar import *
except ImportError as e:
    print '[!] Warning! You do not have a dependency installed for showing the progress bar.'
    exit(1)
try:
    from gmplot import *
except ImportError as e:
    print '[!] Warning! You do not have a dependency installed for gmplot.'
    exit(1)

PROGRAM = 'IPLookup'
VERSION = '1.0.1'
AUTHOR = 'Daniel Ford'
lat = []
lng = []
label = []
marker_color = []
rate_limit = False

# Have to sign up for an account on Cymon.io to get API key
Cymon_api_key = '' # Only get a 1000 requests per day

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
    global marker_color
    global rate_limit
    global key
    global keyDone
    if Bar and not output == 'SingleIP':
        bar = Bar('Analyzing', max=len(ips), suffix='%(index)d/%(max)d - Elapsed: %(elapsed_td)s - Remaining: %(eta_td)s')
    elif output == 'SingleIP':
        print '[*] Analyzing IP Address: %s' % ips[0]
    if len(ips) > 1:
        csvfile = open(output, 'wb')
        writer = csv.writer(csvfile, delimiter=',', quotechar='\"')
        writer.writerow(['IP', 'Risk Rating', 'Reputation Score', 'Times Blacklisted', 'Tor Node', 'Tags', 'Country', 'Region', 'City', 'Hostname', 'ISP', 'Latitude/Longitude', 'Reputation URL', 'Blacklist URL', 'Location URL'])
    if not output == "SingleIP":
        bar.start()
    for i in ips:
        # Get Location Info
        where = []
        loc_url = 'http://ipinfo.io/%s/' % i
        info = requests.get(loc_url)
        ipinfo = info.json()
        try:
            country = ipinfo["country"]
            country = COUNTRY_NAME[country]
            where.append(country)
        except:
            print "\n[!] No info for %s! Could be a private IP!" % i
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
            hostname = ""
            hostname = "".join([x for x in hostname if ord(x) < 128])
        try:
            isp = ipinfo["org"]
            isp = "".join([x for x in isp if ord(x) < 128])
        except:
            isp = ""
            isp = "".join([x for x in isp if ord(x) < 128])
        try:
            loc = ipinfo["loc"]
        except:
            loc = ""
        where = ", ".join([x for x in where if x])

        # Get reputation score
        rep_score = ''
        score_line = False
        first_time = True
        rep_url = "http://reputationauthority.org/lookup?ip=%s" % i
        while True:
            try:
                rep = requests.get(rep_url)
                break
            except:
                if first_time:
                    print "\n[!] Reputation Authority is down!"
                    print "[*] Waiting 30 seconds and trying again..."
                    first_time = False
                else:
                    print "[!] Reputation Authority is still down!"
                    print "[*] Waiting another 30 seconds and trying again..."
            time.sleep(30)
        rep = rep.text.split("\n")
        for line in rep:
            if 'Reputation Score' in line:
                score_line = True
            elif score_line:
                rep_score = line
                rep_score = rep_score[rep_score.find('>')+1:rep_score.rfind('<')]
                rep_score = rep_score.strip()
                break

        # Determine if it has been blacklisted
        blacklist_score = ''
        requests.get('http://www.ipvoid.com/update-report/%s/' % i)
        blacklist_url = 'http://www.ipvoid.com/scan/%s/' % i
        while(True):
            try:
                blacklist = requests.get(blacklist_url)
                break
            except:
                print "\n[!] Failed to reach IPVoid!"
                print "[*] Waiting 10 seconds and trying again..."
            time.sleep(10)
        blacklist =  blacklist.text.split("\n")
        for line in blacklist:
            if 'Report not found' in line:
                blacklist_payload = {'ip':i}
                session = requests.session()
                tmp = requests.post('http://www.ipvoid.com/', data=blacklist_payload)
                blacklist = requests.get(blacklist_url)
                blacklist =  blacklist.text.split("\n")
            if 'Blacklist Status' in line:
                end = line.rfind('</span>')
                start = line[:end].rfind('<span')
                blacklist_score = line[start+1:end]
                blacklist_score = blacklist_score[blacklist_score.find('>')+1:]
                blacklist_score = blacklist_score.split()[-1]
                blacklist_score = blacklist_score.split("/")[0]
                break
        if not blacklist_score:
            blacklist_score = "No Data Available"

        # Associated tags from Cymon.io
        tags = []
        headers = {'Authorization':'Token %s' % Cymon_api_key}
        getTags = requests.get("https://cymon.io:443/api/nexus/v1/ip/%s/events/" % i, headers=headers)
        dTags = getTags.json()

        if rate_limit:
            tags = "Rate Limited, rerun later!"
        elif getTags.status_code == 200:
            if dTags["count"] > 0:
                for item in dTags["results"]:
                    if not item["tag"] in tags:
                        tags.append(item["tag"])
        elif getTags.status_code == 401:
            print "\n[!] Error! Token is not valid!"
            print "[!] Response: %s" % dTags['detail']
            exit(1)
        elif getTags.status_code == 404:
            print "\n[!] Error! Bad request!"
            print "[!] Response: %s" % dTags['detail']
        elif getTags.status_code == 429:
            print "\n[!] Error! Got Rate Limited on Cymon.io!"
            # print "[!] Response: %s" % dTags['detail']
            print "[*] Please check API console to see how many requests you have left."
            rate_limit = True
        elif getTags.status_code == 500:
            print "\n[!] Error! API Error"
            print "[!] Response: %s" % dTags['detail']
        tags = ", ".join(tags)
        if not tags:
            tags = 'None'

        # Determine color of marker and risk (Minimal,Low,Medium,High) based on rep_score, if it has a tag, and if has been blacklisted
        risk = ''
        risk_color = ''
        rep_score_color = rep_score.split("/")[0]
        if rep_score_color:
            rep_score_color = int(rep_score_color)
            try:
                blacklist_score_color = int(blacklist_score)
            except:
                pass
            if rep_score_color <= 50 and not blacklist_score_color == 0 and not tags == 'None':
                marker_color.append('orange')
                risk_color = 'orange'
                risk = 'Medium'
            elif rep_score_color <= 50 and blacklist_score_color == 0 and not tags == 'None':
                marker_color.append('yellow')
                risk_color = 'gold'
                risk = 'Low'
            elif rep_score_color <= 50 and not blacklist_score_color == 0 and tags == 'None':
                marker_color.append('yellow')
                risk_color = 'gold'
                risk = 'Low'
            elif rep_score_color <= 50 and blacklist_score_color == 0 and tags == 'None':
                marker_color.append('green')
                risk_color = 'green'
                risk = 'Minimal'
            elif rep_score_color > 50 and rep_score_color <= 70 and not blacklist_score_color == 0 and not tags == 'None':
                marker_color.append('red')
                risk_color = 'red'
                risk = 'High'
            elif rep_score_color > 50 and rep_score_color <= 70 and blacklist_score_color == 0 and not tags == 'None':
                marker_color.append('orange')
                risk_color = 'orange'
                risk = 'Medium'
            elif rep_score_color > 50 and rep_score_color <= 70 and not blacklist_score_color == 0 and tags == 'None':
                marker_color.append('orange')
                risk_color = 'orange'
                risk = 'Medium'
            elif rep_score_color > 50 and rep_score_color <= 70 and blacklist_score_color == 0 and tags == 'None':
                marker_color.append('yellow')
                risk_color = 'gold'
                risk = 'Low'
            elif rep_score_color > 70 and rep_score_color <= 90 and not tags == 'None':
                marker_color.append('red')
                risk_color = 'red'
                risk = 'High'
            elif rep_score_color > 70 and rep_score_color <= 90 and not blacklist_score_color == 0:
                marker_color.append('red')
                risk_color = 'red'
                risk = 'High'
            elif rep_score_color > 70 and rep_score_color <= 90:
                marker_color.append('orange')
                risk_color = 'orange'
                risk = 'Medium'
            elif rep_score_color > 90:
                marker_color.append('red')
                risk_color = 'red'
                risk = 'High'
        else:
            marker_color.append('white')
            risk_color = 'black'
            risk = 'Insufficient Data'
            rep_score = 'No Data Available'

        # Find if IP is a Tor Node
        tor_url = 'https://torstatus.blutmagie.de/tor_exit_query.php'
        tor_payload = {'QueryIP':i}
        session = requests.session()
        tor_request = requests.post(tor_url, data=tor_payload)
        if "The IP Address you entered matches" in tor_request.text:
            tor = "Yes"
        elif "The IP Address you entered is NOT" in tor_request.text:
            tor = "No"
        else:
            print "[!] Error! Response not found, check code!"

        if output == "SingleIP":
            # Print out results
            print '[+] Analysis Done!'
            print '\n[*] Risk Rating:\t%s' % risk
            print '\n[*] Location:\t\t%s' % where
            print '[*] Hostname:\t\t%s' % hostname
            print '[*] ISP:\t\t%s' % isp
            print '[*] Reputation Score:\t%s' % rep_score
            print '[*] Times Blacklisted:\t%s' % blacklist_score
            print '[*] Tor Node:\t\t%s' % tor
            print '[*] Tags:\t\t%s' % tags
            print '\n[+] Links:'
            print '[*] IP Info URL:\t%s' % loc_url
            print '[*] Blacklist URL:\t%s' % blacklist_url
            print '[*] Reputation URL:\t%s' % rep_url
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
            label.append("<h1>%s</h1><small>%s</small><hr><p>Risk Rating: <b style=color:%s>%s</b></p><p><a href='%s'>Reputation Score:</a> %s</p><p><a href='%s'>Times Blacklisted:</a> %s</p><p>Tor Node: %s</p><p>Tags: %s</p>" % (i,where,risk_color,risk,rep_url,rep_score,blacklist_url,blacklist_score,tor,tags))

            writer.writerow([i,risk,rep_score,blacklist_score,tor,tags,country,region,city,hostname,isp,loc,rep_url,blacklist_url,loc_url])
            count_analyzed += 1
            bar.next()
    bar.finish()
    return [len(ips),count_analyzed, count_not_analyzed]

def createMap(lat, lng, map_loc):
    gmap = gmplot.GoogleMapPlotter(21.9452245, -1.0986107, 3)
    for i in range(0, len(lat)-1):
        gmap.marker(float(lat[i]), float(lng[i]), marker_color[i], label=label[i])
        gmap.circle(float(lat[i]), float(lng[i]), 500, marker_color[i], ew=2)
        gmap.draw(map_loc)

    # Save map as a complete HTM file (Under Development...)


if __name__ == '__main__':
    c = ArgumentParser(description='%s: analyzes an IP or a list of IPs and determines risk associated with those IPs.' % PROGRAM, version=VERSION, epilog='Developed by ' + AUTHOR + ' as an open source tool.')
    c.add_argument('-i', help='input file', required=True)
    c.add_argument('-o', help='output CSV file', required=False)
    c.add_argument('-m', help='Creates a map to view the information on it', required=False, action='store_true')
    c.add_argument('--ip_column', help='coulmn in the CSV file with the IP addresses (starting with 0)', required=False)

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
