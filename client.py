import socket
import ssl
import time

server_ip = "192.168.68.63"   
server_port = 8443   	
interval = 5         	

context = ssl.create_default_context()                  # create an ssl context
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE  

def connect_ssl():
	try:
		sock = socket.create_connection((server_ip, server_port), timeout=5)            # connect to the server over TCP
		print(f"[✓] TCP connection established with {server_ip}:{server_port}")
		ssl_sock = context.wrap_socket(sock, server_hostname=server_ip)                 # initiate SSL handshake over the TCP socket
		print(f"[✓] SSL handshake completed with {server_ip}:{server_port}")
		message = "Hello!\n"
		ssl_sock.sendall(message.encode())
		try:
			data = ssl_sock.recv(1024)
			if data:
				print(f"[<] Received from server: {data.decode().strip()}")
		except socket.timeout:
			pass
		ssl_sock.close()
		print("[✓] Connection closed cleanly.\n")

	except Exception as e:
		print(f"[!] Error: {e}\n")

if __name__ == "__main__":
	print(f"[~] Starting loop to connect to {server_ip}:{server_port} every {interval} seconds...\n")
	try:
		while True:
			connect_ssl()
			time.sleep(interval)
	except KeyboardInterrupt:
		print("\n[!] Stopped by user.")



