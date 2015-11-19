#!/usr/bin/env python

##################### ver 3.0

from snmpEngine import MftSNMP
import argparse

from texttable import Texttable
import os, time

def main():

	##################### ARGPARSE Configuration

	parser = argparse.ArgumentParser(description='Retrieve infos by snmp')

	parser.add_argument('-r','--router', help='router where retrieve parameters',required=False, default="192.168.56.109")
	parser.add_argument('-c','--community', help='snmp community',required=False, default="public")
	parser.add_argument('-d','--debug', help='snmp community',required=False,action="store_true")
	
	parser.add_argument('-i','--ifstat', help='snmp community', required=False, nargs='?', default="off", type=str)
	
	# future
	
	# parser.add_argument('-s','--summary', help='router where retrieve parameters',required=False, action="store_true")
	# parser.add_argument('-c','--compare', help='',required=False)

	args = parser.parse_args()

	##################### 

	r1 = MftSNMP(args.router,args.community)
	
	if args.debug:
		print r1

	# print r1.show_interfaces()
	# print r1.ifStatEngine(5,"KB",1)

	
	### control -i options
	if args.ifstat is not 'off':
		if args.ifstat is None:
			r1.ifstat("None")
		else:
			r1.ifstat(args.ifstat)
			
	# print r1.summary()
	
	r1.walkInterfaces()
		
if __name__ == "__main__":
	main()
