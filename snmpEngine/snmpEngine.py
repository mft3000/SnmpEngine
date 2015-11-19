#!/usr/bin/env python

##################### ver 3.2
#
# Macos
#
# brew install libsmi
# easy_install snimpy
#
# /usr/local/Cellar/libsmi/0.4.8/share/mibs/iana/
#
#
# Debian
#
# apt-get install python-dev build-essential
# apt-get install libffi-dev libsmi-dev 
# easy_install snimpy
#
# vi /etc/apt/sources.list
# ... main non-free 
#
# apt-get update snmp-mibs-downloader
# dpkg --configure -a
# download-mibs
#
# ls /usr/share/mibs/ietf
#
# apt-get install smitools
# smilint -s -l1 CISCO-CDP-MIB.my 
#
#####################

import os, argparse, json, collections, time, re, logging


from snimpy.manager import Manager as M
from snimpy.manager import load
from pyasn1.type import univ

try:
	from ipcalc import Network
except:
	os.system("sudo pip install ipcalc")
	from ipcalc import Network

try:
	from termcolor import colored
except:
	os.system("sudo pip install termcolor")
	from termcolor import colored

try:
	from texttable import Texttable
except:
	os.system("sudo pip install texttable")
	from texttable import Texttable

try:
	import logging
except:
	os.system("sudo pip install logging")
	import logging
	
def convertMac(octet):
	"""
	This Function converts a binary mac address to a hexadecimal string representation
	"""
	mac = [binascii.b2a_hex(x) for x in list(octet)]
 	 ":".join(mac)
 
def convertIP(octet):
	ip = [str(int(binascii.b2a_hex(x),16)) for x in list(octet)]
	return ".".join(ip)

# ++++++++++++++++++++
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
# --------------------	

############## Load MIBs

load("RFC1213-MIB")					# sysName, ecc..
load("IF-MIB")						# ifDescr, ecc..
load("IP-FORWARD-MIB")				# routing table
load("IP-MIB")						# ipAddress
load("OSPF-MIB")					# ospf
load("MPLS-L3VPN-STD-MIB")			# vrf
load("MPLS-LDP-STD-MIB")			# ldp
load("BGP4-MIB")					# bgp
load("ISIS-MIB")					# isis

load("RFC1213-MIB")					# tcp sessions

try:
	load("CISCO-CDP-MIB")			# cdp
except:
	print "smilint -s -l1 CISCO-CDP-MIB"
	os.system("smilint -s -l1 CISCO-CDP-MIB")
	os.system("sudo wget ftp://ftp.cisco.com/pub/mibs/v2/CISCO-TC.my -O /usr/local/Cellar/libsmi/0.4.8/share/mibs/iana/CISCO-TC.my")
	os.system("sudo wget ftp://ftp.cisco.com/pub/mibs/v2/CISCO-VTP-MIB.my -O /usr/local/Cellar/libsmi/0.4.8/share/mibs/iana/CISCO-VTP-MIB.my")
	os.system("sudo wget ftp://ftp.cisco.com/pub/mibs/v2/CISCO-SMI.my -O /usr/local/Cellar/libsmi/0.4.8/share/mibs/iana/CISCO-SMI.my")
	os.system("sudo wget ftp://ftp.cisco.com/pub/mibs/v2/CISCO-CDP-MIB.my -O /usr/local/Cellar/libsmi/0.4.8/share/mibs/iana/CISCO-CDP-MIB.my")
	print "Install MIBS for CDP... done"
	print "Restart application!"
	exit()	

def minimize(string):		# shortnet for interface names (to save space in print)
	if "GigabitEthernet" in string:
		return string.replace("GigabitEthernet","Gi")	
	if "FastEthernet" in string:
		return string.replace("FastEthernet","Fe")
	elif "Loopback" in string:
		return string.replace("Loopback","Lo")
	elif "Mgm" in string:
		return string.replace("MgmtEth","Mgt")
	else:
		return string
		
def expand(string):			# expand for interface names
	if "Gi" in string:
		return string.replace("Gi","GigabitEthernet")
	else:
		return string
	
tree = lambda: collections.defaultdict(tree)

class MftSNMP(object):

	snmpCommunity = "public"
	snmpTarget = ""
	host = ""
	
	intfs = []
	vrfs = []
	arps = []
	onbrs = []
	ldps = []
	
	cdpEns = []
	cdpEntrys = []
		
	snmpDevice = tree()

	def __init__(self, target, community):
		
		self.snmpTarget = target
		self.snmpCommunity = community
		m = M(host=self.snmpTarget, community=self.snmpCommunity, version=2, none=True)

		##################### methods

		for val in m.ifIndex.keys():
			self.intfs.append( \
				[val, \
				m.ifDescr[val], \
				m.ifAlias[val], \
				m.ifMtu[val], \
				str(m.ifAdminStatus[val])[:-3], \
				str(m.ifOperStatus[val])[:-3], \
				m.ifType[val], \
				m.ifPhysAddress[val]] \
				)
			
		ips = []
		for val in m.ipAdEntIfIndex:
			ips.append( \
				(m.ifDescr[m.ipAdEntIfIndex[val]], \
				m.ipAdEntAddr[val], \
				m.ipAdEntNetMask[val]) \
				)
			
		for v in m.mplsL3VpnIfVpnClassification.keys():
			self.vrfs.append( \
				(v[0], \
				m.ifDescr[v[1]]) \
				)
			
		for i in m.ipNetToMediaPhysAddress:
			self.arps.append( \
				(m.ifDescr[i[0]], \
				i[1], \
				m.ipNetToMediaPhysAddress[i]) \
				)
			
		tcps = []
		for i in m.tcpConnLocalAddress:
			tcps.append( \
				(i[0], \
				i[1], \
				i[2], \
				i[3]) \
				)
			
		#"#"#"#"#"# da rifare
		ospfareas = []

		area = dict()
		areatype = dict()
		areatype2 = dict()

		for index1,val1 in enumerate(m.ospfAreaId.iteritems()):
			area[index1] = val1[1]
		for index1,val1 in enumerate(m.ospfImportAsExtern.iteritems()):
			areatype[index1] = val1[1]
		for index1,val1 in enumerate(m.ospfAreaSummary.iteritems()):
			areatype2[index1] = val1[1]
			
		areaintfs = []
		for en,i in enumerate(m.ospfIfIpAddress):
			for v in m.ipCidrRouteIfIndex: 
				if str(i[0]) == v[0]:
					#print str(i[2])[:-2]
					areaintfs.append( \
						[i[0],\
						m.ifDescr[m.ipCidrRouteIfIndex[v]], \
						m.ospfIfAreaId[i], \
						m.ospfIfHelloInterval[i], \
						m.ospfIfRtrDeadInterval[i], \
						m.ospfIfType[i], \
						m.ospfIfRtrPriority[i], \
						m.ospfIfDesignatedRouter[i], \
						m.ospfIfBackupDesignatedRouter[i]] \
						)
					
					for metric in m.ospfIfMetricIpAddress:
						if m.ospfIfMetricIpAddress[metric] == i[0]:
							areaintfs[en].append( \
								m.ospfIfMetricValue[metric] \
								)

		############## Interface Auth

		
		for nbr in m.ospfNbrIpAddr:
			self.onbrs.append( \
				[m.ospfNbrRtrId[nbr], \
				m.ospfNbrIpAddr[nbr], \
				m.ospfNbrPriority[nbr], \
				m.ospfNbrState[nbr], \
				bin(m.ospfNbrOptions[nbr])] \
				)

		for i in m.mplsLdpPeerTransportAddr:
			for v in m.ipCidrRouteIfIndex: 
				if str(i[2])[:-2] == v[0]:
					#print str(i[2])[:-2]
					self.ldps.append( \
						(i[0], \
						i[1], \
						str(i[2])[:-2], \
						m.ifDescr[m.ipCidrRouteIfIndex[v]]) \
						)
					
		for i in m.cdpInterfaceEnable:
			self.cdpEns.append( \
				(m.ifDescr[i], \
				m.cdpInterfaceEnable[i]) \
				)
			
		for i in m.cdpCacheAddress.keys():
			self.cdpEntrys.append( \
				[m.cdpCacheDeviceId[i], \
				m.ifDescr[i[0]], \
				m.cdpCacheCapabilities[i], \
				m.cdpCacheVersion[i], \
				m.cdpCacheDevicePort[i], \
				m.cdpCacheAddress[i], \
				m.cdpCachePlatform[i]]\
				)

		############## main object

		self.host = str(m.sysName)
		self.snmpDevice[self.host]['global']['sysName'] =  self.host
		self.snmpDevice[self.host]['global']['sysDescr'] = m.sysDescr.replace("\r\n"," ")
		self.snmpDevice[self.host]['global']['sysObjectID'] = str(m.sysObjectID)
		self.snmpDevice[self.host]['global']['sysUpTime'] = str(m.sysUpTime)
		self.snmpDevice[self.host]['global']['sysLocation'] = m.sysLocation

		######## routing

		self.snmpDevice[self.host]['OSPF-MIB']['ospfRouterId'] = str(m.ospfRouterId)

		self.snmpDevice[self.host]['BGP4-MIB']['bgpIdentifier'] = str(m.bgpIdentifier)

		#"#"#"#"#"#"# verificare anche che lo stato sia establish

		lrid = "None"
		for tcp in tcps:
			if str(tcp[1]) == '646' or str(tcp[3]) == '646':
				lrid = tcp[0]

		# self.snmpDevice[self.host]['MPLS-LDP-STD-MIB']['mplsLdpLsrId'] = str(m.mplsLdpLsrId)

		# self.snmpDevice[self.host]['ISIS-MIB']['isisSysID'] = str(m.isisSysID)

		self.snmpDevice[self.host]['CISCO-CDP-MIB']['cdpGlobalRun'] = str(m.cdpGlobalRun)

		######## Interface

		for intf in self.intfs:
			self.snmpDevice[self.host]['interfaces'][intf[1]]['ifDescr'] = intf[1]
			self.snmpDevice[self.host]['interfaces'][intf[1]]['ifIndex'] = intf[0]
			self.snmpDevice[self.host]['interfaces'][intf[1]]['ifAlias'] = intf[2]
			self.snmpDevice[self.host]['interfaces'][intf[1]]['ifMtu'] = intf[3]
			self.snmpDevice[self.host]['interfaces'][intf[1]]['ifAdminStatus'] = intf[4]
			self.snmpDevice[self.host]['interfaces'][intf[1]]['ifOperStatus'] = intf[5]
			self.snmpDevice[self.host]['interfaces'][intf[1]]['ifType'] = intf[6]
			self.snmpDevice[self.host]['interfaces'][intf[1]]['ifPhysAddress'] = convertMac(intf[7])
			
			######## ip address
			
			for ip in ips:
				if intf[1] == ip[0]:
					self.snmpDevice[self.host]['interfaces'][intf[1]]['ipAdEntAddr'] = str(ip[1])
					self.snmpDevice[self.host]['interfaces'][intf[1]]['ipAdEntNetMask'] = str(ip[2])
				
			######## vrf

			for vrf in self.vrfs:
				if intf[1] == vrf[1]:
					self.snmpDevice[self.host]['interfaces'][intf[1]]['MPLS-L3VPN-STD-MIB']['mplsL3VpnVrfName'] = str(vrf[0])
					
			######## ARP
			
			for i,arp in enumerate(self.arps):
				if intf[1] == arp[0]:
					if self.snmpDevice[self.host]['interfaces'][intf[1]]['ipAdEntAddr'] != str(arp[1]): #### da verificare
						self.snmpDevice[self.host]['interfaces'][intf[1]]['ipNetToMediaNetAddress'][i] = str(arp[1]) 
						self.snmpDevice[self.host]['interfaces'][intf[1]]['ipNetToMediaPhysAddress'][i] = str(arp[2])
			
			######## OSPF
			
			for areaintf in areaintfs:
				if intf[1] == areaintf[1]:
					self.snmpDevice[self.host]['interfaces'][intf[1]]['OSPF-MIB']['ospfIfAreaId'] = str(areaintf[2])
					self.snmpDevice[self.host]['interfaces'][intf[1]]['OSPF-MIB']['ospfIfHelloInterval'] = int(str(areaintf[3]).replace('.',''))
					self.snmpDevice[self.host]['interfaces'][intf[1]]['OSPF-MIB']['ospfIfRtrDeadInterval'] = int(str(areaintf[4]).replace('.',''))
					self.snmpDevice[self.host]['interfaces'][intf[1]]['OSPF-MIB']['ospfIfType'] = str(areaintf[5])
					self.snmpDevice[self.host]['interfaces'][intf[1]]['OSPF-MIB']['ospfIfRtrPriority'] = int(str(areaintf[6]).replace('.',''))
					self.snmpDevice[self.host]['interfaces'][intf[1]]['OSPF-MIB']['ospfIfDesignatedRouter'] = str(areaintf[7])
					self.snmpDevice[self.host]['interfaces'][intf[1]]['OSPF-MIB']['ospfIfBackupDesignatedRouter'] = str(areaintf[8])
					self.snmpDevice[self.host]['interfaces'][intf[1]]['OSPF-MIB']['ospfIfMetricValue'] = int(str(areaintf[9]).replace('.',''))
					# snmpDevice[host]['interfaces'][intf[1]]['OSPF-MIB']['area type'] = ""
					# snmpDevice[host]['interfaces'][intf[1]]['OSPF-MIB']['area no summary'] = ""
					# snmpDevice[host]['interfaces'][intf[1]]['OSPF-MIB']['int auth'] = ""
					
					############## OSPF Neighbors filterd per interface
					for i,onbr in enumerate(self.onbrs):
						# print intf[1]
						if str(onbr[1]) in Network(self.snmpDevice[self.host]['interfaces'][intf[1]]['ipAdEntAddr'] + "/" + self.snmpDevice[self.host]['interfaces'][intf[1]]['ipAdEntNetMask']):
							self.snmpDevice[self.host]['interfaces'][intf[1]]['OSPF-MIB']['adj'][i]['ospfNbrRtrId'] = str(onbr[0])
							self.snmpDevice[self.host]['interfaces'][intf[1]]['OSPF-MIB']['adj'][i]['ospfNbrIpAddr'] = str(onbr[1])
							self.snmpDevice[self.host]['interfaces'][intf[1]]['OSPF-MIB']['adj'][i]['ospfNbrPriority'] = str(onbr[2]).replace('.','')
							self.snmpDevice[self.host]['interfaces'][intf[1]]['OSPF-MIB']['adj'][i]['ospfNbrState'] = str(onbr[3])[:-3]
							self.snmpDevice[self.host]['interfaces'][intf[1]]['OSPF-MIB']['adj'][i]['ospfNbrOptions'] = str(onbr[4])
							
					############## MPLS LDP Neighbors

					for i,ldp in enumerate(self.ldps):
						if intf[1] == ldp[3] :
							self.snmpDevice[self.host]['interfaces'][intf[1]]['mplsLdpStdMIB']['adj'][i]['ospfNbrRtrId'] = str(ldp[2])
								
			############## CDP Neighbors filterd per interface 
			
			for cdpEn in self.cdpEns:
				if intf[1] == cdpEn[0]:
					self.snmpDevice[self.host]['interfaces'][intf[1]]['CISCO-CDP-MIB']['cdpInterfaceEnable'] = str(cdpEn[1])[:-3]
					if str(cdpEn[1])[-2] == "1":
						for i,cdpEntry in enumerate(self.cdpEntrys):					
							self.snmpDevice[self.host]['interfaces'][intf[1]]['CISCO-CDP-MIB'][i]['cdpCacheDeviceId'] = str(cdpEntry[0])
							self.snmpDevice[self.host]['interfaces'][intf[1]]['CISCO-CDP-MIB'][i]['cdpCacheDevicePort'] = str(cdpEntry[4])
							slef.snmpDevice[self.host]['interfaces'][intf[1]]['CISCO-CDP-MIB'][i]['cdpCacheAddress'] = convertIP(cdpEntry[5])
							self.snmpDevice[self.host]['interfaces'][intf[1]]['CISCO-CDP-MIB'][i]['cdpCachePlatform'] = str(cdpEntry[6])

	def __str__(self):
		return json.dumps(self.snmpDevice, sort_keys=True, indent=4, separators=(',', ': '))

	def show_interfaces(self):

		### build table with interfaces
		table = Texttable()
		table.set_cols_align(["c", "l", "l", "l", "l", "l"])
		data = [["ifIndex","ifDescr","ifAlias","IPadd","AS","OS"]]
		for line,interface in enumerate(self.snmpDevice[self.host]['interfaces']):
			### check if the interface has an ip address
			if self.snmpDevice[self.host]['interfaces'][interface]['ipAdEntAddr']:
				data.append([str(self.snmpDevice[self.host]['interfaces'][interface]['ifIndex']), \
						minimize(str(self.snmpDevice[self.host]['interfaces'][interface]['ifDescr'])), \
						str(self.snmpDevice[self.host]['interfaces'][interface]['ifAlias']), \
						str(self.snmpDevice[self.host]['interfaces'][interface]['ipAdEntAddr']), \
						str(self.snmpDevice[self.host]['interfaces'][interface]['ifAdminStatus']), \
						str(self.snmpDevice[self.host]['interfaces'][interface]['ifOperStatus']), \
						])
			else:
				data.append([str(self.snmpDevice[self.host]['interfaces'][interface]['ifIndex']), \
						minimize(str(self.snmpDevice[self.host]['interfaces'][interface]['ifDescr'])), \
						str(self.snmpDevice[self.host]['interfaces'][interface]['ifAlias']), \
						"--", \
						str(self.snmpDevice[self.host]['interfaces'][interface]['ifAdminStatus']), \
						str(self.snmpDevice[self.host]['interfaces'][interface]['ifOperStatus']), \
						])

		table.add_rows(data, header=True)

		return table.draw()
		

	def ifStatEngine(self,choice,speedUnit="kb",secDelta=5):

		### delta time bw two probes
		sec = secDelta

		### first probe
		m = M(host=self.snmpTarget,community=self.snmpCommunity,none=True)

		intfsOne = []
		for val in m.ifIndex.keys():
			if str(val) == str(choice):
				intfsOne.append(int(val))
				intfsOne.append(str(m.ifDescr[val]))
				intfsOne.append(int(m.ifHCOutOctets[val]))
				intfsOne.append(int(m.ifHCInOctets[val]))
				intfsOne.append(int(m.ifHighSpeed[val]))
				intfsOne.append(str(m.ifAlias[val]))

		# print intfsOne
		time.sleep(sec)

		### first probe
		m = M(host=self.snmpTarget,community=self.snmpCommunity,none=True)

		intfsTwo = []
		for val in m.ifIndex.keys():
			if str(val) == str(choice):
				intfsTwo.append(int(val))
				intfsTwo.append(str(m.ifDescr[val]))
				intfsTwo.append(int(m.ifHCOutOctets[val]))
				intfsTwo.append(int(m.ifHCInOctets[val]))
				intfsTwo.append(int(m.ifHighSpeed[val]))
				intfsTwo.append(str(m.ifAlias[val]))

		# print intfsTwo

		# if interface has no HC speed attribute (like Loopback, null, ecc), set default interface speed
		if intfsOne[4] == 0:
			speed = 1000
		else:
			speed = intfsOne[4]

		# calc speed based speedUnit set
		if "kb" in speedUnit:		
			inSpeed =  (((intfsTwo[2]-intfsOne[2]) * 8 * 100) / (sec * speed)) / 1024
			outSpeed = (((intfsTwo[3]-intfsOne[3]) * 8 * 100) / (sec * speed)) / 1024

		# return Out, In speed
		return float(outSpeed), float(inSpeed)

	def show_interfaces_speed(self, choice):
		
		tree = lambda: collections.defaultdict(tree)
		choice_explode = tree()

		### build table with interfaces and current SPEED/sec
		while True:
			table = Texttable()
			table.set_deco(Texttable.HEADER)
			table.set_cols_align(["c", "l", "l", "l", "l"])
			data = [["ifIndex","ifDescr","ifAlias","Out","In"]]

			for i in range(len(choice)):
				choice_explode[choice[i]]['Out'], choice_explode[choice[i]]['In'] = self.ifStatEngine(int(choice[i]),"kb",1)

			os.system('clear')

			for line,interface in enumerate(self.snmpDevice[self.host]['interfaces']):
				
				for i,ch in enumerate(choice):
					if str(self.snmpDevice[self.host]['interfaces'][interface]['ifIndex']) == str(ch):
						data.append([str(self.snmpDevice[self.host]['interfaces'][interface]['ifIndex']), \
								minimize(str(self.snmpDevice[self.host]['interfaces'][interface]['ifDescr'])), \
								str(self.snmpDevice[self.host]['interfaces'][interface]['ifAlias']), \
								str(choice_explode[ch]['Out']), \
								str(choice_explode[ch]['In']), \
								])	
				### still print other interfaces, # if you don't want print out informations
						break
				if ch not in str(self.snmpDevice[self.host]['interfaces'][interface]['ifIndex']):
					data.append([str(self.snmpDevice[self.host]['interfaces'][interface]['ifIndex']), \
							minimize(str(self.snmpDevice[self.host]['interfaces'][interface]['ifDescr'])), \
							str(self.snmpDevice[self.host]['interfaces'][interface]['ifAlias']), \
							"---", \
							"---", \
							])

			table.add_rows(data, header=True)

			print table.draw()
		exit()

	def ifstat(self,string="None"):
	
		############## ifStat

		if "None" in string:						### -i

			print self.show_interfaces()
			
			print ""
			choice = raw_input("choose interface: ")
			
			### 5,7
			if "," in choice:
				os.system('clear')
				self.show_interfaces_speed(choice.split(","))

		elif re.search('[\d+\,]+', string):		### -i 5[,7]
	
			choice = string
			
			if "," in choice:
				os.system('clear')
				self.show_interfaces_speed(choice.split(","))
				
		elif re.search('\d+', string):				### -i 6

			choice = string
			
		elif re.search('[a-zA-Z]*', string):		### -i GPRX

			m = M(host=self.snmpTarget,community=self.snmpCommunity,none=True)

			choice = None
			for val in m.ifIndex.keys():
				if str(m.ifAlias[val]) == string:
					choice = val
					
		print ""
		for i in self.snmpDevice[self.host]['interfaces']:
			if int(choice) == self.snmpDevice[self.host]['interfaces'][i]['ifIndex']:
				print self.snmpDevice[self.host]['interfaces'][i]['ifIndex'], " - ",self.snmpDevice[self.host]['interfaces'][i]['ifDescr']
				print "\'" + str(self.snmpDevice[self.host]['interfaces'][i]['ifAlias']) + "\'"

		print "\nOut\tIn"
		while True:
			OutSpeed, inSpeed = self.ifStatEngine(choice,"kb",1)
			print OutSpeed, "\t", inSpeed

	def summary(self):
		print "hostname", self.snmpDevice[self.host]['global']['sysName']
		print "OSPF RID", self.snmpDevice[self.host]['OSPF-MIB']['ospfRouterId']
		print "BGP RID", self.snmpDevice[self.host]['BGP4-MIB']['bgpIdentifier']
		print "Interface no.", len(self.snmpDevice[self.host]['interfaces'])
		print "OSPF Adjacency", len(self.onbrs)
		print "LDP Adjacency", len(self.ldps)
		
	def walkInterfaces(self):
		### cicle on interfaces
		for int in self.snmpDevice[self.host]['interfaces']:
			print "*",self.snmpDevice[self.host]['interfaces'][int]['ifDescr']
			# if interface own an ip address
			if self.snmpDevice[self.host]['interfaces'][int]["ipAdEntAddr"]:
				# if interface belong into vrf
				if self.snmpDevice[self.host]['interfaces'][int]["MPLS-L3VPN-STD-MIB"]:
					# if interface has an ip arp neighbors
					if len(self.snmpDevice[self.host]['interfaces'][int]['ipNetToMediaNetAddress']) is not 0:
						# show ip arp neighbors belong on this interface 
						for arp in self.snmpDevice[self.host]['interfaces'][int]['ipNetToMediaNetAddress']:
							# print vrf XXX arp neighbor
							
							print " pint vrf", self.snmpDevice[self.host]['interfaces'][int]["MPLS-L3VPN-STD-MIB"]['mplsL3VpnVrfName'], \
								self.snmpDevice[self.host]['interfaces'][int]['ipNetToMediaNetAddress'][arp]
							print " telnet", self.snmpDevice[self.host]['interfaces'][int]['ipNetToMediaNetAddress'][arp], \
								"/vrf ",self.snmpDevice[self.host]['interfaces'][int]["MPLS-L3VPN-STD-MIB"]['mplsL3VpnVrfName']
				# if interface do not belong into vrf
				else:
					# if interface has an ip arp neighbors
					if len(self.snmpDevice[self.host]['interfaces'][int]['ipNetToMediaNetAddress']) is not 0:
						# show ip arp neighbors belong on this interface 
						for arp in self.snmpDevice[self.host]['interfaces'][int]['ipNetToMediaNetAddress']:
							# print arp neighbor
							print " ping", self.snmpDevice[self.host]['interfaces'][int]['ipNetToMediaNetAddress'][arp]
							print " telnet ", self.snmpDevice[self.host]['interfaces'][int]['ipNetToMediaNetAddress'][arp]
