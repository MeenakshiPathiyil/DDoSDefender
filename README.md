# DDoS Defender
A python-based DDoS detection and mitigation system that monitors raw TCP traffic to identify SYN flood attacks and incomplete handhsakes, using iptables to block suspicious IPs in real time.

## Features
- Detects abnormal SYN flood patterns using raw sockets
- Tracks TCP handshakes and SSL completions to distinguish legitimate clients from attackers
- Dynamically blocks malicious IPs with iptables

## Requirements
- Python 3.x
- Root privileges (required for raw sockets and iptables)

## Generate SSL Certificate
```openssl req -new -x509 -days 365 -nodes -out cert.pem -keyout key.pem```

## Usage
- Start the receiver:  
``` sudo python3 receiver.py ```      
- Start the legitimate client:   
``` sudo python3 client.py ```  
- Simulate the attack:  
``` sudo python3 attacker.py ```  

## Detection Logic 
- Monitors SYN vs ACK count per IP
- Blocks IPs with incomplete handshakes beyond a configurable threshold
- Allows IPs showing valid SSL handshakes

## Note
Built for educational and research purposes to simulate and mitigate DDoS attacks at the network layer
