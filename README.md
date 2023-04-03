# covert_channel
A covert channel that utilizes TTL and QoS headers (+ proxy IDS/IPS for it)

Each one of the modules should be run in a separate machine. All of the machines must be in the same network ( NAT network, perhaps?:) )

client 1 is legitimate and does not know a thing about a covert channel - just sends UDP packets to security proxy

Somewhere between the Secuirty proxy and the Client 1 there is sniffer that intercepts the packets and modifies the TTL and ToS headers

Sec proxy either detects modifications to TTL and ToS headers, or modifies them beforehand to prevent the channel

client 2 knows about the covert channel and reads the messages from headers ( if any at all)
