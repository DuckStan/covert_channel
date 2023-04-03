from scapy.all import *
import argparse



client1_ip = "192.168.121.198"
client1_port = 12346
client2_ip = "192.168.121.199"
client2_port = 12348
sec_proxy_ip = "192.168.121.150"
sec_proxy_port = 1337


global encoded_ttls
global counter
global final_counter
global covert_mode
global secret_message
#encoded_ttls = encode_message_ttl(secret_message)
counter = 0
#final_counter = len(encoded_ttls)

def encode_message_ttl(message):
    # Convert the message to binary
    binary_message = ''.join(format(ord(char), '08b') for char in message)
    print(binary_message)
    # Encode the binary message in the TTL field of the IP header
    encoded_ttl = []
    for bit in binary_message:
        if bit == '0':
            encoded_ttl.append(20)
        elif bit == '1':
            encoded_ttl.append(200)

    return encoded_ttl

def handle_packet(packet):
    #print("PACKET!")
    global encoded_ttls
    global counter
    global final_counter
    global covert_mode
    global secret_message

    # Modify TTL to 200 for all packets received on port 12348
    if packet.haslayer(IP) and packet[IP].ttl == 64:
        # Create a new IP packet and copy relevant fields from original packet
        new_pkt = IP(src=packet[IP].src, dst=packet[IP].dst)
        new_pkt /= packet[UDP]

        # Modify the TTL field in the new packet
        if counter < final_counter:
            if (covert_mode == 'ttl'):
                new_pkt.ttl = encoded_ttls[counter]
            elif (covert_mode == 'qos'):
                new_pkt.tos = ord(secret_message[counter])
            else:
                raise Exception("Something messy with a covert mode!")
        else:
            new_pkt.ttl = 32
            counter = 0
        counter += 1
        # Send the new packet

        send(new_pkt, verbose=1)




def parse_arguments():
    parser = argparse.ArgumentParser(description='Covert channel emulation', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-f', '--filename', help='data to tranfer via covert channel', required=True, dest='filename', type=str, default='test')
    parser.add_argument('-m', '--mode', help='covert mode',choices = ['ttl', 'qos'], required=True, dest='mode', type=str, default='ttl')
    
    return parser.parse_args()

def main():
    global covert_mode
    global secret_message
    global final_counter
    global encoded_ttls

    args = parse_arguments()
    fname = args.filename   
    covert_mode = args.mode
    
    text_file = open(fname, "r")
    #read whole file to a string
    secret_message = text_file.read()
    #close file
    text_file.close()
    
    if (covert_mode == 'ttl'):
        encoded_ttls = encode_message_ttl(secret_message)
        final_counter = len(encoded_ttls)
    elif (covert_mode == 'qos'):
        final_counter = len(secret_message)
    else:
        raise Exception("Something messy with a covert mode!")
    sniff(filter="dst port " + str(sec_proxy_port) + " and dst host " + sec_proxy_ip + " and src host " + client1_ip, prn=handle_packet, iface ="eth0")


if __name__ == "__main__":
    main()
