#!/usr/bin/python

import os
import datetime
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
# import urllib3
# urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import csv
import time
import random
import json
from json import load
import socket
from urllib2 import urlopen
from argparse import ArgumentParser
from iso_country_codes import COUNTRY_NAME
try:
    import dns.resolver
except ImportError as e:
    print '[!] Warning! You do not have a dependency installed for dns.resolver'
    print '[!] Run `pip install dnspython` and rerun program'
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
VERSION = '1.6'
AUTHOR = 'Daniel Ford'
lat = []
lng = []
label = []
marker_color = []
rate_limit = False

# Have to sign up for an account on Cymon.io to get API key
Cymon_api_key = '' # Only get a 1000 requests per day
# Rook's Grunt API key (This your API key located in Preforce >> Help >> Token)
rook_api = ''

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
                except Exception as e:
                    print '[-] Error parsing the IP from the following line:\n\t%s' % line
    return ips

def Client_IP_Check(ip):
    url = "https://preforce.rook.net/api/is_client"

    querystring = {"ip_address":ip}

    headers = {
        'authorization': "Token %s" % rook_api,
        'cache-control': "no-cache"
    }
    response = requests.request("GET", url, headers=headers, verify=False, params=querystring)

    ip_data = None
    try:
        ip_data = json.loads(response.text)
    except Exception, e:
        error = {
            "e": str(e),
            "url": url,
            "response": str(response),
            "response.text": str(response.text)
        }
        print error

    if not ip_data['is_client'] == "False":
        ip_data = ip_data['is_client']
        ip_data = ip_data[ip_data.find(':')+2:ip_data.rfind('-')-1]
        return ip_data
    else:
        return None

def analyzeIPs(ips, output, client_check):
    count_not_analyzed = 0
    customer = None
    high_risk = 0
    medium_risk = 0
    low_risk = 0
    minimal_risk = 0
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
        if client_check == "Yes":
            print '[*] Checking to see if client IP...'
            customer = Client_IP_Check(ips[0])
            if customer:
                print '[!] IP ADDRESS IS %s\'s! DO NOT BLOCK!\n' % customer
            else:
                print '[*] IP address is not a client IP.\n'
        print '[*] Analyzing IP Address: %s' % ips[0]
    if len(ips) > 1:
        csvfile = open(output, 'wb')
        writer = csv.writer(csvfile, delimiter=',', quotechar='\"')
        writer.writerow(['IP', 'Risk Rating', 'Reputation Score', 'Blacklist Status', 'Alien Vault', 'Cymon.io Tags', 'Country', 'Region', 'City', 'Hostname', 'ISP', 'Latitude/Longitude', 'Reputation URL', 'Alien Vault URL', 'Cymon.io URL', 'Location URL'])
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
                    print "[*] Waiting 60 seconds and trying again..."
                    first_time = False
                else:
                    print "[!] Reputation Authority is still down!"
                    print "[*] Waiting another 60 seconds and trying again..."
            time.sleep(60)
        rep = rep.text.split("\n")
        for line in rep:
            if 'Reputation Score' in line:
                score_line = True
            elif score_line:
                rep_score = line
                rep_score = rep_score[rep_score.find('>')+1:rep_score.rfind('<')]
                rep_score = rep_score.strip()
                if not rep_score.split("/")[0]:
                    rep_score = 'No Data Available'
                break

        # Determine if it is on Alien Vault
        alien_data = ''
        alien_url = 'https://www.alienvault.com/open-threat-exchange/dashboard#/my/reputation-monitor/%s' % i
        alien_request_url = 'https://www.alienvault.com/apps/api/threat/ip/%s' % i
        while(True):
            try:
                alien = requests.get(alien_request_url)
                break
            except:
                print "\n[!] Failed to reach alienvault.com!"
                print "[*] Waiting 10 seconds and trying again..."
            time.sleep(10)
        alien_data = alien.json()

        try:
            if alien_data['activity_types']:
                alien_data = alien_data['activity_types']
                alien_data = str(alien_data).split('\'')[1]
            else:
                alien_data = "No Data Available"
        except:
                print alien_data

        # Determine how many times it has been blacklisted
        bls = ["0spam.fusionzero.com","access.redhawk.org","all.rbl.jp",
                "all.s5h.net","all.spamrats.com","b.barracudacentral.org",
                "bb.barracudacentral.org","bl.spamcop.net","blacklist.woody.ch",
                "block.dnsbl.sorbs.net","cbl.abuseat.org","cblplus.anti-spam.org.cn",
                "cdl.anti-spam.org.cn","combined.abuse.ch","db.wpbl.info",
                "dnsbl-0.uceprotect.net","dnsbl-1.uceprotect.net","dnsbl-2.uceprotect.net",
                "dnsbl-3.uceprotect.net","dnsbl.inps.de","dnsbl.kempt.net",
                "dnsbl.justspam.org","dnsbl.sorbs.net","dnsbl.spfbl.net",
                "drone.abuse.ch","dul.dnsbl.sorbs.net","dul.ru",
                "dyna.spamrats.com","escalations.dnsbl.sorbs.net","http.dnsbl.sorbs.net",
                "httpbl.abuse.ch","ips.backscatterer.org","korea.services.net",
                "misc.dnsbl.sorbs.net","new.spam.dnsbl.sorbs.net","noptr.spamrats.com",
                "old.spam.dnsbl.sorbs.net","pbl.spamhaus.org","problems.dnsbl.sorbs.net",
                "proxies.dnsbl.sorbs.net","psbl.surriel.com","rbl.efnet.org",
                "rbl.efnetrbl.org","rbl.interserver.net","recent.spam.dnsbl.sorbs.net",
                "relays.bl.kundenserver.de","relays.dnsbl.sorbs.net","safe.dnsbl.sorbs.net",
                "sbl-xbl.spamhaus.org","sbl.spamhaus.org","short.rbl.jp",
                "smtp.dnsbl.sorbs.net","socks.dnsbl.sorbs.net","spam.abuse.ch",
                "spam.dnsbl.sorbs.net","spam.spamrats.com","spamsources.fabel.dk",
                "web.dnsbl.sorbs.net","xbl.spamhaus.org","zen.spamhaus.org"]
        blacklist_count = 0
        blacklist_reported = []
        for bl in bls:
            try:
                my_resolver = dns.resolver.Resolver()
                query = '.'.join(reversed(str(i).split("."))) + "." + bl
                my_resolver.timeout = 5
                my_resolver.lifetime = 5
                answers = my_resolver.query(query, "A")
                answer_txt = my_resolver.query(query, "TXT")
                blacklist_count = blacklist_count + 1
                blacklist_reported.append(bl)
            except dns.resolver.NXDOMAIN:
                pass
            except dns.resolver.Timeout:
                pass
            except dns.resolver.NoNameservers:
                pass
            except dns.resolver.NoAnswer:
                pass

        if blacklist_count == 0:
            blacklist_data = "Not Blacklisted"
            blacklist_reported = "Not on any blacklists"
        else:
            blacklist_data = "Blacklisted (%s/60)" % blacklist_count
            blacklist_reported = ', '.join(blacklist_reported)

        # Associated tags from Cymon.io
        tags = []
        tags_url = "https://cymon.io/%s" % i
        headers = {'Authorization':'Token %s' % Cymon_api_key}
        getTags = requests.get("https://cymon.io:443/api/nexus/v1/ip/%s/events/" % i, headers=headers)
        temp = 0
        while(True):
            if not getTags and temp < 5:
                print "\n[!] Failed to reach Cymon.io!"
                print "[*] Waiting 5 seconds and trying again..."
            else:
                break
            time.sleep(5)
            getTags = requests.get("https://cymon.io:443/api/nexus/v1/ip/%s/events/" % i, headers=headers)
            temp += 1
        if not getTags and temp > 4:
            print "\n[!] Failed to reach Cymon.io after 5 tries!"
            print "[*] Moving to next IP..."
            writer.writerow([i,'Insufficient Data',rep_score,blacklist_count,alien_data,"",country,region,city,hostname,isp,loc,rep_url,alien_url,tags_url,loc_url])
            bar.next()
            temp = 0
            continue
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
        risk_score = 0
        rep_score_temp = rep_score.split("/")[0]
        if rep_score_temp:
            rep_score_temp = int(rep_score_temp)
        if rep_score_temp > 70:
            risk_score += 1
        if not alien_data == "No Data Available":
            risk_score += 1
        if blacklist_count > 1:
            risk_score += 1
        if not tags == 'None':
            risk_score += 1
        if risk_score > 0 and customer == None:
            if risk_score == 1:
                marker_color.append('yellow')
                risk_color = 'gold'
                risk = 'Low'
                low_risk += 1
            elif risk_score == 2:
                marker_color.append('orange')
                risk_color = 'orange'
                risk = 'Medium'
                medium_risk += 1
            elif risk_score >= 3:
                marker_color.append('red')
                risk_color = 'red'
                risk = 'High'
                high_risk += 1
        elif not customer == None:
            customer = Client_IP_Check(i)
            marker_color.append('white')
            risk_color = 'black'
            risk = '%s\'s IP' % customer
        else:
            marker_color.append('green')
            risk_color = 'green'
            risk = 'Minimal'
            minimal_risk += 1

        if output == "SingleIP":
            # Print out results
            print '[+] Analysis Done!'
            print '\n[*] Risk Rating:\t%s' % risk
            print '\n[*] Location:\t\t%s' % where
            print '[*] Hostname:\t\t%s' % hostname
            print '[*] ISP:\t\t%s' % isp
            print '[*] Reputation Score:\t%s' % rep_score
            print '[*] Blacklist Status:\t%s' % blacklist_data
            print '[*] Alien Vault:\t%s' % alien_data
            print '[*] Cymon.io Tags:\t%s' % tags
            print '\n[+] Sources:'
            print '[*] IP Info URL:\t%s' % loc_url
            print '[*] Reputation URL:\t%s' % rep_url
            print '[*] Blacklists:\t\t%s' % blacklist_reported
            print '[*] Alien Vault URL:\t%s' % alien_url
            print '[*] Cymon.io URL:\t%s' % tags_url
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
            label.append("<h1>%s</h1><small>%s</small><hr><p>Risk Rating: <b style=color:%s>%s</b></p><p><a href='%s'>Reputation Score:</a> %s</p><p>Times Blacklisted:</a> %s</p><p><a href='%s'>Alien Vault:</a> %s</p><p>Tags: %s</p>" % (i,where,risk_color,risk,rep_url,rep_score,blacklist_count,alien_url,alien_data,tags))

            writer.writerow([i,risk,rep_score,blacklist_data,alien_data,tags,country,region,city,hostname,isp,loc,rep_url,alien_url,tags_url,loc_url])
            bar.next()
    bar.finish()
    return [len(ips),count_not_analyzed, high_risk, medium_risk, low_risk, minimal_risk]

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
    c.add_argument('-c', help='Check to see if the IP is the client\'s IP address', required=False, action='store_true')
    c.add_argument('-m', help='Creates a map to view the information on it', required=False, action='store_true')
    c.add_argument('--ip_column', help='coulmn in the CSV file with the ips (starting with 0)', required=False)

    args = c.parse_args()

    if args.c:
        my_ip = load(urlopen('http://jsonip.com'))['ip']
        ip_check = my_ip.rsplit('.',1)[0]
        if ip_check == '209.43.126':
            client_check = "Yes"
        else:
            print '[-] Error! You are not on Rook\'s network!'
            print '[-] Please connect to VPN before running client check'
            print 'Exiting program...'
            exit(1)
    else:
        client_check = "No"

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
                print "[!] Will not be able to run all %s IPs in a 24hr period! Rate limit issues..." % len(ips)
                cont = raw_input('[?] Continue? (Y/n) ')
                if cont.lower() in ['n', 'no']:
                    print 'Exiting program...'
                    exit(1)
            print '[*] Analyzing %d IPs...' % len(ips)
            results = analyzeIPs(ips, args.o, client_check)
            print '\n[+] Analysis complete. CSV output saved to: %s' % args.o
            if args.m:
                print '\n[*] Creating map with location data...'
                map_loc = args.o[:args.o.rfind(".")] + ".html"
                createMap(lat,lng,map_loc)
                print '[+] Map complete. Map saved to: %s' % map_loc
            end_time = datetime.datetime.now()
            run_time = end_time - start_time
            print '\n[*] IPs provided:\t%d' % results[0]
            print '[*] IPs NOT analyzed:\t%d' % results[1]
            print '\n[*] High Risk IPs:\t%d' % results[2]
            print '[*] Medium Risk IPs:\t%d' % results[3]
            print '[*] Low Risk IPs:\t%d' % results[4]
            print '[*] Minimal Risk IPs:\t%d' % results[5]
            print '\n[*] Total runtime:\t%s' % str(run_time)[:-5]
        else:
            print '[!] Error! Need to supply an output CSV file!'
            exit(1)
    else:
        if args.o:
            print '[!] Warning! Will not save output for single IP!'
        try:
            ip = IPAddress(args.i)
            analyzeIPs([args.i],"SingleIP", client_check)
        except ValueError as e:
            print '[!] Invalid input type! Please only input a single IP, CSV file, or Text File!'
