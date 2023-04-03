import threading
import time
import socket
from scapy.all import *

client1_ip = "192.168.121.198"
client1_port = 12346
client2_ip = "192.168.121.199"
client2_port = 12348
sec_proxy_ip = "192.168.121.150"
sec_proxy_port = 1337


s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((client1_ip, client1_port))

def listen_and_send():
    # Listen for incoming messages on client 1


    # Send messages to client 2 periodically
    while True:
        message = "Hello!"
        #print(message)
        s.sendto(message.encode(), (sec_proxy_ip, sec_proxy_port))
        time.sleep(10)


def receive(packet):
    # Listen for incoming messages on client 1
    #s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #s.bind((client1_ip, client1_port_l))
    # Receive messages from client 2
    #while True:
    #    data, addr = s.recvfrom(1024)
    #    print(f"Received message: {data.decode()}")
    data = bytes(packet[0][Raw].load)
    #print(data)
    print(f"Received message: {data.decode()}")
    #return
    #time.sleep(1)

def main():
    # Start client 1 in a separate thread
    t1 = threading.Thread(target=listen_and_send)
    t1.start()

    # Start client 1 in the main thread
    #t2 = threading.Thread(target=receive)
    #t2.start()
    sniff(filter="udp and dst port " + str(client1_port) + " and dst host " + client1_ip, prn=receive, iface = 'enp0s3', count=0)



if __name__ == "__main__":
    main()
