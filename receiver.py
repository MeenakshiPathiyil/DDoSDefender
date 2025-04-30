import socket
import time
import subprocess
import ssl
import threading
import struct

# Thresholds
syn_inspection_threshold = 20               # evaluate IPs after every 20 SYNs
block_duration = 60
incomplete_handshake_ratio = 0.8            # If more than 80% of SYNs are incomplete, it's suspicious 

# Tracking
ip_stats = {}    
blocked_ips = {}
total_syn_count = 0

# Parses IP headers to extract protocol, source IP, and destination IP
def parse_ip_header(data):
	ip_hdr = struct.unpack('!BBHHHBBH4s4s', data[:20])
	protocol = ip_hdr[6]
	src_ip = socket.inet_ntoa(ip_hdr[8])
	dst_ip = socket.inet_ntoa(ip_hdr[9])
	return protocol, src_ip, dst_ip

# Parses TCP header to extract source/destination port, and TCP flags 
def parse_tcp_header(data):
	tcp_hdr = struct.unpack('!HHLLBBHHH', data[20:40])
	src_port = tcp_hdr[0]
	dst_port = tcp_hdr[1]
	flags = tcp_hdr[5]
	syn = (flags & 0x02) >> 1
	ack = (flags & 0x10) >> 4
	return src_port, dst_port, syn, ack

# Uses iptables to drop incoming packets from the given IP
def block_ip(ip):
	if ip not in blocked_ips:
		print(f"[!] Blocking IP: {ip}")
		subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
		blocked_ips[ip] = time.time()

# After the block duraction, removes IPs from the block list
def unblock_ips():
	now = time.time()
	for ip in list(blocked_ips.keys()):
		if now - blocked_ips[ip] > block_duration:
			print(f"[+] Unblocking IP: {ip}")
			subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
			del blocked_ips[ip]

# Calculates how many TCP handshakes were not completed and how many SSL handshakes were attempted
def evaluate_ip(ip):
	stats = ip_stats[ip]
	syns = stats["syn"]
	completes = stats["completed"]
	ssl = stats.get("ssl", 0)
	if syns == 0:
		return False
	ratio = (syns - completes) / syns
	ssl_ratio = ssl / completes if completes > 0 else 0
	if ratio >= incomplete_handshake_ratio and ssl_ratio < 0.2:
		return True
	return False

# Accept SSL connections 
def ssl_server():
	context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
	context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

	bindsocket = socket.socket()
	bindsocket.bind(('', 8443))
	bindsocket.listen(5)
	print("[*] SSL server running on port 8443")

	while True:
		try:
			newsocket, fromaddr = bindsocket.accept()
			ip = fromaddr[0]
			ssl_conn = context.wrap_socket(newsocket, server_side=True)
			print(f"[✓] SSL connection established from {ip}")
			if ip in ip_stats:
				ip_stats[ip]["ssl"] = ip_stats[ip].get("ssl", 0) + 1
			ssl_conn.close()
		except Exception as e:
			print(f"[!] SSL error: {e}")

ssl_thread = threading.Thread(target=ssl_server, daemon=True)
ssl_thread.start()

# Packet receiving function
def receive_packet():
	global total_syn_count
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
	while True:
		packet = s.recvfrom(65565)[0]
		protocol, src_ip, dst_ip = parse_ip_header(packet)
		if protocol == socket.IPPROTO_TCP:
			src_port, dst_port, syn, ack = parse_tcp_header(packet)
			if src_ip not in ip_stats:
				ip_stats[src_ip] = {"syn": 0, "completed": 0, "ssl": 0, "last_syn_time": 0}
			if syn and not ack:
				ip_stats[src_ip]["syn"] += 1
				ip_stats[src_ip]["last_syn_time"] = time.time()
				total_syn_count += 1
				print(f"[>] SYN from {src_ip} (Total SYNs: {total_syn_count})")
			elif ack:
				if ip_stats[src_ip]["syn"] > ip_stats[src_ip]["completed"]:
					ip_stats[src_ip]["completed"] += 1
					print(f"[✓] TCP handshake complete from {src_ip}")
		unblock_ips()
		if total_syn_count >= syn_inspection_threshold:
			print(f"[!] Evaluating IPs after {total_syn_count} SYNs...")
			for ip in list(ip_stats.keys()):
				if evaluate_ip(ip):
					block_ip(ip)
			total_syn_count = 0

# Start packet receiving in a background thread
packet_thread = threading.Thread(target=receive_packet, daemon=True)
packet_thread.start()

# Evaluate and block IP addresses periodically
while True:
	unblock_ips()
	time.sleep(1)