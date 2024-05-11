from scapy.all import sniff

def packet_callback(packet):
    if packet.haslayer('IP'):
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst
        
        if packet.haslayer('TCP'):
            src_port = packet['TCP'].sport
            dst_port = packet['TCP'].dport
            protocol = 'TCP'
        elif packet.haslayer('UDP'):
            src_port = packet['UDP'].sport
            dst_port = packet['UDP'].dport
            protocol = 'UDP'
        else:
            src_port = 'N/A'
            dst_port = 'N/A'
            protocol = 'N/A'
        
        print(f"Source IP: {src_ip}, Source Port: {src_port}, Destination IP: {dst_ip}, Destination Port: {dst_port}, Protocol: {protocol}")

def start_sniffing(interface):
    sniff(iface=interface, prn=packet_callback, store=0)

def main():
    interface = 'eth0'  # Change this to your network interface
    start_sniffing(interface)