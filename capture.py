import os
import sys
import urllib
import urllib2
from urllib2 import urlopen
import argparse
import re
import socket
import pyshark
import dns.resolver
import subprocess


packet_count=0

capture = pyshark.LiveCapture(interface='eth0') #capture from eth0
packet_iterator = capture.sniff_continuously 	#capture continuously

IP_exclude = ['noip'] # exclude RPIs and Routers own IP addresses
Safe_IPs = [] # list to be appended with IPs already checked

#router_exclude = ['18:31:bf:67:74:f0',] #exclude router mac address to assign router IP
#RPI_exclude =  ['b8:27:eb:8f:c4:da', '01:80:c2:00:00:00' , '01:80:c2:00:00:0e'] #exclude RPIs default network MACs to assing default IP

def content_test(url, packet_ip):

	try:
		request = urllib2.Request(url)
		opened_request = urllib2.build_opener().open(request)
		html_content = opened_request.read()
		retcode = opened_request.code

		matches = retcode == 200
		matches = matches and re.findall(packet_ip, html_content)
		return len(matches) == 0
	except Exception, e:
		print "Error! %s" % e
		return False


def blockip(packet_ip):
	cmd="sudo /sbin/iptables -A INPUT -s "+packet_ip+" -j DROP"
	print cmd
	subprocess.call(cmd,shell=True)

bls = ["ipbl.zeustracker.abuse.ch", "bl.spamcop.net", "b.barracudacentral.org","pbl.spamhaus.org", "xbl.spamhaus.org", "zen.spamhaus.org"]

URLS = [
    #TOR
	('http://torstatus.blutmagie.de/ip_list_exit.php/Tor_ip_list_EXIT.csv',
	 'is not a TOR Exit Node',
	 'is a TOR Exit Node',
     False),

    #EmergingThreats
    ('http://rules.emergingthreats.net/blockrules/compromised-ips.txt',
	 'is not listed on EmergingThreats',
	 'is listed on EmergingThreats',
	 True),]


for packet in capture.sniff_continuously(): #Iterating forever when in continuous mode.
	BAD = 0
	GOOD = 0
	if("IP" in str(packet.layers)): #Read IP address from IP Layer
		packet_ip = packet.ip.addr
	else:							# If packet has no IP Layer assign with "noip" and discarded (packets from networks router etc)
		packet_ip = 'noip'

	if packet_ip not in IP_exclude and packet_ip not in Safe_IPs:

		for url, succ, fail, mal in URLS:
			if content_test(url, packet_ip):
				print'{0} {1}'.format(packet_ip, succ)
				GOOD = GOOD + 1
			else:
				print'{0} {1}'.format(packet_ip, fail)
				BAD = BAD + 1

		BAD = BAD
		GOOD = GOOD
		
		if BAD < 1:
		
			for bl in bls: # checking IP against DNS Blacklists
				try:
					my_resolver = dns.resolver.Resolver()
					query = '.'.join(reversed(str(packet_ip).split("."))) + "." + bl
					my_resolver.timeout = 5
					my_resolver.lifetime = 5
					answers = my_resolver.query(query, "A")
					answer_txt = my_resolver.query(query, "TXT")
					#print packet_ip + ' is listed in ' + bl + ' (%s: %s)' % (answers[0], answer_txt[0])
					BAD = BAD + 1

				except dns.resolver.NXDOMAIN:
					print packet_ip + ' is not listed in ' + bl
					GOOD = GOOD + 1

				except dns.resolver.Timeout:
					print 'WARNING: Timeout querying ' + bl

				except dns.resolver.NoNameservers:
					print 'WARNING: No nameservers for ' + bl

				except dns.resolver.NoAnswer:
					print 'WARNING: No answer for ' + bl
			#print "{0} is on {1}/{2} blacklists.\n" .format(packet_ip, BAD, (GOOD+BAD))
		
			if BAD > 0:
				blockip(packet_ip)
				print "WARNING"
			else:
				Safe_IPs.append(packet_ip)
				print "SAFE IP"
		else:
			if ["$(sudo cat /sbin/iptables --list | grep -- packet_ip)"]:
				print "Already Blocked"
			else:
				blockip(packet_ip)
				print "IP Blocked"
