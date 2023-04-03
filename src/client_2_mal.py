import threading
import time
from scapy.all import *
import argparse

client1_ip = "192.168.121.198"
client1_port = 12346

client2_ip = "192.168.121.199"
client2_port = 12348

sec_proxy_ip = "192.168.121.150"
sec_proxy_port = 1337

global covert_mode
global secret_message
global secret_message_b
secret_message = ""
secret_message_b = ""

global s
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((client2_ip, client2_port))


def read_ttl_secret(ttl):
    if ttl <= 20:
        return "0"
    elif ttl <=200 and ttl > 128:
        return "1"
    elif ttl == 32:
        return "END"
    else:
        return "NONE"

def receive_and_send():
    global s 
    # Listen for incoming messages on client 2


    # Send messages to client 1 periodically
    while True:
        message = "Hello to you too!"
        s.sendto(message.encode(), (sec_proxy_ip, sec_proxy_port))
        time.sleep(10)

def process_ttl(ttl):
    global secret_message
    global secret_message_b

    val = read_ttl_secret(ttl)
    if val != "NONE":
        if val != "END":
            secret_message_b += val
            print(secret_message_b)
        else:
            binary_int = int(secret_message_b, 2);

            # Getting the byte number
            byte_number = (binary_int.bit_length() + 7) // 8

            # Getting an array of bytes
            binary_array = binary_int.to_bytes(byte_number, "big")

            # Converting the array into ASCII text
            secret_message = binary_array.decode("ascii")
            print(f"SECRET MESSAGE IS: {secret_message}")

def process_qos(qos):
    global secret_message
    secret_message += chr(qos)
    print(secret_message)

def receive(packet):
    # Listen for incoming messages on client 2
    global covert_mode
    global secret_message
    global secret_message_b
    # Receive messages from client 1
    

    ttl = packet[0][IP].ttl
    if packet[0][IP].tos:
        qos = packet[0][IP].tos
    else:
        qos = 0

    data = bytes(packet[0][Raw].load)
    #print(data)
    if (covert_mode == 'ttl'):
        process_ttl(ttl)
    elif (covert_mode == 'qos'):
        process_qos(qos)
    else:
        raise Exception("Something messy with a covert mode")

    print(f"Received message: {data.decode()}, TTL: {ttl}, QoS: {qos}")
    #return
    #time.sleep(1)


def parse_arguments():
    parser = argparse.ArgumentParser(description='Covert channel emulation', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    #parser.add_argument('-f', '--filename', help='data to tranfer via covert channel', required=True, dest='filename', type=str, default='test')
    parser.add_argument('-m', '--mode', help='covert mode',choices = ['ttl', 'qos'], required=True, dest='mode', type=str, default='ttl')
    
    return parser.parse_args()
                
def main():
    #global s
    global covert_mode
    args = parse_arguments()
    #fname = args.filename   
    covert_mode = args.mode

    # Start client 2 in a separate thread
    t1 = threading.Thread(target=receive_and_send)
    t1.start()

    # Start client 2 in the main thread
    #t2 = threading.Thread(target=receive)
    #t2.start()
    #while True:
    sniff(filter="udp and dst port " + str(client2_port) + " and dst host " + client2_ip, prn=receive, iface = 'enp0s3', count=0)
    

if __name__ == "__main__":
    main()
