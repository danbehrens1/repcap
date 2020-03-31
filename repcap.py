#repcap.py
#version 1.0
#Python 3
#Requires scapy - tested/developed with 2.4.3
#Project to allow users to modify packet captures and replay them
#Author: Daniel Behrens - dabehren@cisco.com
# Command Line Tool that takes in arguments
# Current version supports 5 modes: passed to tool via -m command
# 0 - the ability to identify IP and MAC addresses in a packet capture - default when no mode provided
# 1 - the ability to replay a packet capture unaltered - must include interface to send it
# 2 - the ability to read in a packet capture and rewrite the ips and create a new packet capture file (.pcap)
# 3 - the ability to read and rewrite ( same as 2 ) and then replay the capture ( with interface presented )
# 4 - a walk through to create a configuration file that will be used by modes 1 - 3



import logging, sys, getopt, os.path
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

infile = 'none'
interface = 'none'
outputfile = 'none'
configfile = 'none'
mode = 0

#Supported file types - pcap and pcapng today
ALLOWED_EXTENSIONS = {'pcap', 'pcapng'}


def allowed_file(filename):
# Quick function to validate file type / extension
	return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def mainargs(argv):
# Take arguments from command and assign to runtime parameters
	global cwd, interface, mode, configfile, outputfile
	try:
		opts, args = getopt.getopt(argv, "hm:i:c:o:", ["mode=","interface=","config=","outfile="])
	except getopt.GetoptError:
		printhelp()
	for opt, arg in opts:
		if opt == '-h':
			printhelp()
			sys.exit()
		elif opt in ("-m", "--mode"):
			mode = arg
		elif opt in ("-i", "--interface"):
			interface = arg
		elif opt in ("-c", "--config"):
			configfile = arg
		elif opt in ("-o", "--outfile"):
			outputfile = arg
	#print("Selected Mode is ",mode)
	#print(argv[len(argv)-1])

def printhelp():
	# Function to print the help information when -h is invoked or incorrect commands provided
	print("_________________________________________________")
	print("usage: repcap.py <options> inputfile")
	print("inputfile must be .pcap or .pcapng")
	print("example: repcap.py example1.pcap - will list unique ip and mac addresses in example1.pcap")
	print("example: repcap.py -m 1 -i en0 example1.pcap - will replay example1.pcap unaltered out interface en0")
	print("example: repcap.py -m 4 example1.pcap - will guide through creating a config file and output example1.config")
	print("_________________________________________________")
	print("options:")
	print("-m  mode  see mode section below")
	print("-i  target interface - used for packet replay - name of interface")
	print("-c  configuration file - if not provided will look for default which is based on name of provided pcap <name of sourcefile>.config")
	print("-o  output file - if not provided will use name of <name of sourcefile>new.pcap")
	print("_________________________________________________")
	print("modes:")
	print("1 = replay packet capture unaltered - must include -i option for interface")
	print("2 = read config file and rewrite IPs from source packet capture and create new file")
	print("3 = read config file and rewrite IPs from source packet capture, create new file and replay - must include -i option for interface")
	print("4 = guided mode for packet rewrite - will create .config text file")
	

def findUniqueIP(pcap):
	# Function to identify all the unique source / destination IP and MAC addresses in a packet capture ( and sort )
	print("Loading Packet Capture")
	uniqueip = {}
	uniquesortedip = {}
	packets = rdpcap(pcap)
	for p in packets:
		if p.haslayer(IP):
			if p[IP].src not in uniqueip:
				uniqueip[str(p[IP].src)] = str(p[Ether].src)
			elif p[IP].dst not in uniqueip:
				uniqueip[str(p[IP].dst)] = str(p[Ether].dst)
	for ip in sorted(uniqueip.keys(), key = lambda ip: (int(ip.split(".")[0]), int(ip.split(".")[1]), int(ip.split(".")[2]), int(ip.split(".")[3]))):
		uniquesortedip[ip] = uniqueip[ip] 
		
	return uniquesortedip

def replaypackets(pcap, inter):
	# Function to replay a packet capture - used for mode 1 and 3
	print("Reading Packet Capture ")
	packets = rdpcap(pcap)
	print("Starting Packet Replay")
	sendp(packets, iface=str(inter), verbose=False)
	print("Packet Replay Complete")	

def validateipformat(ip):
	# Function to validate IP address is in the right format
	myregex = "^((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\.(?!$)|$)){4}$"
	return re.fullmatch(myregex, ip, flags=0)

def validatemacformat(mac):
	# Function to validate MAC address is in the right format
	myregex = "^([0-9A-Fa-f]{2}[:]){5}([0-9A-Fa-f]{2})$"
	return re.fullmatch(myregex, mac, flags=0)
	
def configbreakdown(configurationfile):
	# Function to read in a configuration file and pull out the IP and MAC changes in the file
	macdict = {}
	ipdict = {}
	cf = open(configurationfile, 'r')
	for line in cf:
		nowhite = line.strip()
		if nowhite.split(',')[0] == "ip":
			if nowhite.split(',')[2] == "Del":
				print("Deleting " +  nowhite.split(',')[1])
			elif validateipformat(nowhite.split(',')[2]) and validateipformat(nowhite.split(',')[1]):
				ipdict[(nowhite.split(',')[1])] = nowhite.split(',')[2]
			else:
				print("Configuration File Formatting Error, please go through mode 4 to create a new file")
				print(nowhite)
				sys.exit()
		elif nowhite.split(',')[0] == "mac":
			if validatemacformat(nowhite.split(',')[1]) and validatemacformat(nowhite.split(',')[2]):
				macdict[(nowhite.split(',')[1])] = nowhite.split(',')[2]
			else:
				print("Configuration File Formatting Error, please go through mode 4 to create new file")
				print(nowhite)
				sys.exit()
		else:
			print("Configuration File Formatting Error, please go through mode 4 to create new file")
			print(nowhite)
			sys.exit()

	return macdict, ipdict

def namebreakdown(inputpcapname):
	# Function to break down a file and get the name and extension as a list
	pcapfilenamepath = inputpcapname.strip()
	pcapfilenamepath = pcapfilenamepath.split("/")
	pcapfilenamepath = pcapfilenamepath[len(pcapfilenamepath) - 1]
	pcapfilenamepath = pcapfilenamepath.split(".")
	return pcapfilenamepath
	

def packetrewrite(macdict, ipdict, pcap):
	# Function that takes in MAC address and IP Dictionary to rewrite existing IP and MAC to new ones
	# Checks if the output file already exists and checks prior to over writing the file
	# output file name may be user provided or auto generated based on name of input file
	global outputfile
	loop1 = False
	
	if outputfile == 'none':
		tempname = namebreakdown(pcap)
		outputfile = tempname[0] + "new." + tempname[1]
	
	if os.path.isfile(outputfile):
		print("_________________________________________________")
		loop1 = True
		while loop1 == True:
			docontinue = input(outputfile + " already exists! This action will overwrite existing file. enter Y to proceed or N to cancel:") 
			if str(docontinue) == "N":
				loop1 = False
				sys.exit()
			elif str(docontinue) == "Y":
				loop1 = False
	else:
		print(outputfile + " not found, creating new file")

	print("Reading in Packets from " + pcap)
	packets = rdpcap(pcap)
	print("Re-writing Packets")
	
	for p in packets:
		if p.haslayer(IP):
			del p[IP].chksum
			if p[IP].src in ipdict:
				p[IP].src = ipdict[p[IP].src]
			if p[IP].dst in ipdict:
				p[IP].dst = ipdict[p[IP].dst]
			if p[Ether].src in macdict:
				p[Ether].src = macdict[p[Ether].src]
			if p[Ether].dst in macdict:
				p[Ether].dst = macdict[p[Ether].dst]
		if p.haslayer(TCP):
			del p[TCP].chksum
	
	wrpcap(outputfile, packets)
	print("Packets rewritten to " + outputfile) 

def modezero():
	# Mode 0 Function - default if no mode provided in command - print list of unique IP and MAC addresses
	uniqueip = findUniqueIP(infile)
	print("Unique IP and MAC addresses in Source PCAP: ")
	for ip, mac in uniqueip.items():
		print(ip + "   " + mac)
	sys.exit()

def modeone():
	# Mode 1 Function - replay provided packet capture without any changes
	global cwd, interface, mode, configfile, outputfile
	
	if interface == 'none':
		print("Error: Interface must be provided with Mode 1 command. See 'repcap.py -h' for command help")
		sys.exit()
	else:
		replaypackets(infile, interface)

def modetwo():
	# Mode 2 Function - does a packet capture rewrite and outputs to a new file
	# Takes in a configuration file and a source packet capture. User can provide a name for the new packet capture
	# or will create a packet capture based on the source file name ( with new )
	global cwd, interface, mode, configfile, outputfile, infile
	cwd = os.path.abspath(os.path.dirname(sys.argv[0]))
	resultdict = {}
	if configfile == 'none':
		tempname = namebreakdown(infile)
		cfname = cwd + '/' + tempname[0] + ".config"
	else:
		cfname = configfile
	if os.path.isfile(cfname):
			print(cfname + " found - using for configuration")
			resultdict = configbreakdown(cfname)
	else:
		print(cfname + " not found and no configuration file provided. See 'repcap.py -h' for command help")
		sys.exit()

	packetrewrite(resultdict[0], resultdict[1], infile) 
	
	
def modethree():
	# Mode 3 Function - does a packet capture rewrite and outputs to a new file and replays that new file
	# Takes in a configuration file and a source packet capture. User can provide configuration file or looks for default
	# Default Configuration file name is source file name with .config extension 
	# User can provide a name for the new packet capture
	# or will create a packet capture based on the source file name ( with new )
	global cwd, interface, mode, configfile, outputfile, infile
	cwd = os.path.abspath(os.path.dirname(sys.argv[0]))
	if interface == 'none':
		print("Error: Interface must be provided with Mode 3 command. See 'repcap.py -h' for command help")
		sys.exit()
	elif configfile == 'none':
		tempname = namebreakdown(infile)
		cfname = cwd + '/' + tempname[0] + ".config"
	else:
		cfname = configfile
	if os.path.isfile(cfname):
			print(cfname + " found - using for configuration")
			resultdict = configbreakdown(cfname)
	else:
		print(cfname + " not found and no configuration file provided. See 'repcap.py -h' for command help")
		sys.exit()

	packetrewrite(resultdict[0], resultdict[1], infile)
	replaypackets(infile, interface)

def modefour():
	# Mode 4 Function - walks users through existing IP Addresses and MAC addresses in provided packet capture
	# User can choose to maintain the same IP/MAC, Change the IP and/or Change the MAC Address or delete the host from the capture
	# User can provide configuration file name or will use the default
	# If file exists, check user wants to overwrite existing file
	# If user chooses to delete an IP Address, the paired MAC is removed as well - so doesn't prompt for details of that
	# User can't choose to delete a MAC address
	global cwd, infile, configfile
	loop1 = False
	skipmac = False
	cwd = os.path.abspath(os.path.dirname(sys.argv[0]))
	if configfile == 'none':
		tempname = namebreakdown(infile)
		cfname = cwd + '/' + tempname[0] + ".config"
	else:
		cfname = configfile
	if os.path.isfile(cfname):
		print("_________________________________________________")
		loop1 = True
		while loop1 == True:
			docontinue = input(cfname + " already exists! This action will overwrite existing file. enter Y to proceed or N to cancel:") 
			if str(docontinue) == "N":
				loop1 = False
				sys.exit()
			elif str(docontinue) == "Y":
				loop1 = False
				cf = open(cfname, 'w')
	else:
		print(cfname + " not found, creating new file")
		cf = open(cfname, 'w')
		
	uniqueip = findUniqueIP(infile)
	# get unique IP and MAC in the pcap
	loop1 = False
	print("_________________________________________________")
	print("")
	print("")
	print("Mode 4 - Guided Mode - Will Prompt for new IP address for each unique IP in provided packet capture file.")
	print("To change, please enter new valid IP address or MAC Address, to keep the same, simply hit enter.")
	print("To remove an IP enter Del. Note - removing an IP will remove the IP/MAC pair")
	for ip, mac in uniqueip.items():
		# prompt for new ip using existing ip - enter to keep same, Del to delete, or new IP
		newip = input(ip + " : ")
		if newip == "":
			# if just hit enter -  just put the same ip
			print(ip)
			cf.write("ip," + ip + "," + ip + '\n')
		elif newip == "Del":
			# if Del entered - put Del in configuration file
			print("Delete")
			cf.write("ip," + ip + "," + "Del" + '\n')
			skipmac = True
			# if Del entered - do not prompt for MAC address change
		else:
			# if not enter or Del - validate provided IP format. If not valid IP, reprompt
			loop1 = True
			while loop1 == True:
				if not validateipformat(newip):
					print("not a valid ipv4 format. Please try again. Should be in x.x.x.x format or Del to delete")
					newip = input(ip + " : ")
				else:
					# if valid IP, write to configuration file - format is word ip, existing IP, new IP
					print(newip)
					cf.write("ip," + ip + "," + newip + '\n')
					loop1 = False
		if skipmac == False:
			# If keeping IP or changing IP - prompt to keep or change MAC address		
			newmac = input(mac + " : ")
			if newmac == "":
				# if just hit enter - just put the same MAC
				# Configuration file format - the word mac, original mac, new mac
				print(mac)
				cf.write("mac," + mac + "," + mac + '\n')
			else:
				loop1 = True
				# if not a valid MAC or just enter - reprompt until valid mac provided
				while loop1 == True:
					if not validatemacformat(newmac):
						print("not a valid MAC address. Please try again. Should be in aa:aa:aa:aa:aa:aa format - Del not valid for MAC address")
						newmac = input(mac + " : ")
					else:
						print(newmac)
						cf.write("mac," + mac + "," + newmac + '\n')
						loop1 = False
		else:
			skipmac = False
	cf.flush()
	cf.close()
	loop1 = True
	while loop1 == True:
		createpcap = input("Create packet capture? (Y or N):")
		if createpcap == "Y":
			modetwo()
			loop1 = False
		elif createpcap == "N":
			loop1 = False
		else:
			print("Not valid input - Y or N")
			
	
	sys.exit()


# Main function
# Validate input packet capture provided ( required for all modes )
# Validate input file is .pcap or .pcapng and that it does exist
# Pass arguments to mainargs to assign run time values
# Call on appropriate mode based on arguments

if __name__ == '__main__':
	if len(sys.argv) < 2:
		print("_________________________________________________")
		print("No inputfile provided.")
		printhelp()
		sys.exit()
	else:
		infile = sys.argv[len(sys.argv)-1]
		if allowed_file(infile):
			if os.path.isfile(infile):
				mainargs(sys.argv[1:])
			else:
				print("File not found - please check path. See 'repcap.py -h' for command help")
				sys.exit()
		else:
			print("Unsupported input file. See 'repcap.py -h' for command help")
			sys.exit()
			
	if int(mode) == 0:
		modezero()
		sys.exit()
	elif int(mode) == 1:
		modeone()
		sys.exit()
	elif int(mode) == 2:
		modetwo()
		sys.exit()
	elif int(mode) == 3:
		modethree()
		sys.exit()
	elif int(mode) == 4:
		modefour()
		sys.exit()
	else:
		print("unsupported mode. See 'repcap.py -h' for command help")	
		


