# ICMPhostdiscovery

Sends icmp packets to a whole given network, every time the script starts generates a random secret encapsulated in every ping request.

## How to run

python3 icmphostdiscover.py --> automatically network is 192.168.1.0 with netmask /24
python3 icmphostdiscover.py <Network ip> --> netmask is /24
python3 icmphostdiscover.py <Network ip> <NetMask>--> ip and mask manually set, don't use '/' for netmask

## Special thanks to Black Hat Python Creators for the project idea
