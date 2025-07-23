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
			print(f"[-] Error when resolving IP for the target {target}: {e}")

def scanPort(ipAddr, port):
    sock = None # This is initialized to None so that if socket.socket() fails,
                # sock is still defined as None, and the 'finally' block can safely check 'if sock:'
                # without raising an UnboundLocalError. It's a common pattern for resource management.

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((ipAddr,port))

        # If connection succeeds, print that the port is open
        print(f"[+] Port {port} is open.") # Removed trailing space here for consistency

        try:
            banner = sock.recv(1024).decode().strip()

            if banner:
                print(f"    [+] Banner: {banner}") # Removed space before colon
            else:
                print(f"    [+] No Banner recieved!")

        except socket.timeout:
            # print(f"    [+] Banner receive timed out") # Keep silent or log to a debug file
            pass
        except Exception as e:
            # print(f"    [+] Unable to detect version: {e}") # Keep silent or log to a debug file
            pass

    except socket.timeout:
        # print(f"[-] Port {port} timed out!") # Keep silent
        pass
    except socket.error as e:
        # print(f"[-] Port {port} is closed or filtered: {e}") # Keep silent
        pass
    except Exception as e:
        # print(f"[-] Unexpected error: {e}") # Keep silent
        pass
    finally:
        if sock:
            sock.close()

def scan(target, portsToScan, scanType="custom"):

	convertedIp = checkIp(target)

	if not convertedIp:
		print(f"[-] Failed to resolve target IP: {target}. Skipping Scan")
		return

	if (scanType=="common"):
		print(f"\n[#] Scanning target: {convertedIp} on common ports {len(portsToScan)} ports")
	if (scanType=="range"):
		print(f"\n[#] Scanning target: {convertedIp} from {min(portsToScan)} to {max(portsToScan)}")
	if (scanType=="list"):
		ipList = ", ".join(map(str, sorted(portsToScan)))
		print(f"\n[#] Scanning target: {convertedIp} on specific ports: {ipList}")
	else:
		ipList = ", ".join(map(str, sorted(portsToScan)))
		print(f"\n[#] Scanning target: {convertedIp} on ports: {ipList}")

	threads = []
	for port in portsToScan:
		thread = threading.Thread(target=scanPort, args=(convertedIp, port))
		threads.append(thread)
		thread.start()

	print(f"[#] Launched {len(threads)} threads. Waiting for them to complete.")
	for thread in threads:
		thread.join()
	print(f"[#] All scanning threads are completed for {convertedIp}")


# main logic summation
if __name__ == "__main__":
	targetsInput = input("[+] Enter target/s to scan (for multiple seperate by commas): ")
	portInput = input("[+] Enter ports to scan (eg. 20 or 20-80 or 20,44,80 or leave blank for common ports): ")
	portInput = portInput.strip().lower() # this is to normalize input for checks

	portsToScan = []
	scanType = "custom"

	# for all common ports
	if not portInput or portInput == "custom" or portInput == "all":
		portsToScan = sorted(list(set(COMMON_PORTS))) # set is for unique
		scanType = "common"

	# for range eg. 20-80
	elif '-' in portInput:
		try:
			parts = portInput.split('-')
			startPort = int(parts[0])
			endPort = int(parts[1])

			# lets validate port numeber (basic range)
			startPort = max(1, min(65535, startPort))
			endPort = max(1, min(65535, endPort))

			if startPort > endPort:
				startPort, endPort = endPort, startPort
			portsToScan = list(range(startPort, endPort + 1))
			scanType = "range"
		except ValueError:
			print("[-] Invalid port range provided. Using common ports")
			portsToScan = sorted(list(set(COMMON_PORTS)))
			scanType = "common"
	
	# for list eg. 20,44,80,103
	elif ',' in portInput:
		try:
			parts = portInput.split(',')
			for pStr in parts:
				p = int(pStr.strip())
				if 1 <= p <= 65535:
					portsToScan.append(p)
				else:
					print(f"[-] Warning: Port {p} is out of valid range 1-65535 and will be skipped") # 0 is reserved
			scanType = "list"
		except ValueError:
			print("[-] Invalid Port list provided. Using common ports")
			portsToScan = sorted(list(set(COMMON_PORTS)))
			scanType = "Common"
	
	# to handle a single port
	else:
		try:
			p = int(portInput.strip())
			if 1 <= p <= 65535:
				portsToScan = [p]
				scanType = "list" # single port as list too
			else:
				print(f"[-] Warning: Port {p} is out of valid range 1-65535 or invalid. Using common ports")
				portsToScan = sorted(list(set(COMMON_PORTS)))
				scanType = "Common"

		except ValueError:
			print("[-] No valid port, range, or list entered. Using common ports.")
			portsToScan = sorted(list(set(COMMON_PORTS)))
			scanType = "common"
	
	if not portsToScan:
		print("[-] No valid ports to scan after parsing input. Exiting")
		sys.exit(0)

	target_list = [t.strip() for t in targetsInput.split(',') if t.strip()]
	
	if not target_list:
		print("[-] No target entered. Exiting.")
		sys.exit(1)
	
	for target in target_list:
		scan(target, portsToScan, scanType)