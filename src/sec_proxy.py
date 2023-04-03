from scapy.all import *
import argparse



client1_ip = "192.168.121.198"
client1_port = 12346

client2_ip = "192.168.121.199"
client2_port = 12348

sec_proxy_ip = "192.168.121.150"
sec_proxy_port = 1337



global sec_mode


def handle_packet(packet):

    global sec_mode

    # Modify TTL to 200 for all packets received on port 12348
    if packet.haslayer(IP):

        # Create a new IP packet and copy relevant fields from original packet
        if packet[IP].src == client1_ip:
            new_pkt = IP(src= packet[IP].src, dst = client2_ip, ttl = packet[IP].ttl, tos = packet[IP].tos)
            #new_pkt[IP].dport = client2_port
            new_pkt /= packet[UDP]
            new_pkt[UDP].dport = client2_port
        elif packet[IP].src == client2_ip:
            new_pkt = IP(src= packet[IP].src, dst = client1_ip, ttl = packet[IP].ttl, tos = packet[IP].tos)
            #new_pkt[IP].dport = client1_port
            new_pkt /= packet[UDP]
            new_pkt[UDP].dport = client1_port

        else:
            raise Exception("WTF WHO ARE YOU IP")
       
        print(new_pkt[IP])
       # new_pkt /= packet[UDP]

        # Modify the TTL field in the new packet
        if (sec_mode == 'detection'):
            if (packet[IP].ttl < 64) or (packet[IP].ttl > 128):
                print("TTL COVERT CHANNEL DETECTED")
            if packet[IP].tos:
                if (packet[IP].tos > 56):
                    print("QoS COVERT CHANNEL DETECTED")
        elif (sec_mode == 'prevention'):
            new_pkt.ttl = 64
            new_pkt.tos = 0 
        else:
            raise Exception("Something messy with the sec mode")
            

        # Send the new packet

        send(new_pkt, verbose=1)




def parse_arguments():
    parser = argparse.ArgumentParser(description='Covert channel emulation', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    #parser.add_argument('-f', '--filename', help='data to tranfer via covert channel', required=True, dest='filename', type=str, default='test')
    parser.add_argument('-m', '--mode', help='covert mode',choices = ['detection', 'prevention'], required=True, dest='mode', type=str, default='detection')
    
    return parser.parse_args()

def main():
    global sec_mode

    args = parse_arguments()
    #fname = args.filename   
    sec_mode = args.mode
    
    sniff(filter="dst port " + str(sec_proxy_port) + " and dst host " + sec_proxy_ip, prn=handle_packet, iface ="enp0s3")


if __name__ == "__main__":
    main()
