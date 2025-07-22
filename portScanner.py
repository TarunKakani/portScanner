from IPy import IP
import socket
import threading
import sys

# nmap uses the most common 1000 ports (from what i have heard & seen) these are some common ports but
# if we want to expand the ports we can use a top-500 or top-1000 port list but will it be effecient with
# multi-threading?
COMMON_PORTS = [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 123, 135, 137, 138, 139,
    143, 161, 162, 389, 443, 445, 500, 514, 520, 523, 546, 547, 587, 636, 993,
    995, 1433, 1521, 1723, 3306, 3389, 5432, 5900, 8000, 8080, 8443
]

def checkIp(target):

	try:
		# will check if its a ip or not
		ip_obj = IP(target)
		return str(ip_obj) # it will return only after if its a validated ip string

	except ValueError:
		# value error will be raised when its not a direct ip but a hostname
		try:
			# we will get the resolved ip through the hostname string
			resolved_ip = socket.gethostbyname(target) # this converts a hostname to ip (q:is this just ipv4 or both)
			return resolved_ip

		except socket.gaierror:
			print(f"[-] Hostname resolution failed for {target}")
		except Exception as e:
			print(f"[-] Error when resolving IP for the target {target} : {e}")

def scanPort(ipAddr, port):
	sock = None # why did we initialize sock to none

	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #ipv4 TCP socket
		
		# set time out for connection & subsequent operations like (recv)
		sock.settimeout(1)

		# attempt connection
		sock.connect((ipAddr,port))

		# if conncetion succeeds
		print(f"[+] Port{port} is open.")

		try:
			# lets attempt to retrive the banner
		

	