import ipaddress
import socket
import struct
import sys
import multiprocessing
import string 
import random 

class IP:
    def __init__(self, buff=None):
           header = struct.unpack('<BBHHHBBH4s4s', buff)
           #shifts the first 4 bits to right -->
           self.ver = header[0] >> 4
           #ip header len 1 bytes AND 0xF (00001111) --> second half of the first byte
           self.ihl = header[0] & 0xF
           self.tos = header[1]
           self.len = header[2]
           self.id = header[3]
           self.offset = header[4]
           self.ttl = header[5]
           self.protocol_num = header[6]
           self.sum = header[7]
           self.src = header[8]
           self.dst = header[9]
           # conver ips to decimal 
           self.src_address = ipaddress.ip_address(self.src) 
           self.dst_address = ipaddress.ip_address(self.dst)
           # map protocol constants to their names
           # https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
           self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
           try:
               self.protocol =self.protocol_map[self.protocol_num]
           except Exception as e:
                print('%s No protocol for %s' % (e,self.protocol_num))
                self.protocol = str(self.protocol_num)

class ICMP:
    def __init__(self,buff = None) :
        rawshit = struct.unpack('<BBHHH',buff)
        self.type = rawshit[0]
        self.code = rawshit[1]
        self.headerchecksum = rawshit[2]
        self.unused = rawshit[3]
        self.nexthopMTU = rawshit[4]

def generate_random_hex_string(length=7):
    hex_characters = string.hexdigits[:-6]  
    random_hex_string = ''.join(random.choice(hex_characters) for _ in range(length))
    return random_hex_string

def listen(secret:str):
    socket_protocol = socket.IPPROTO_IP
    sniffer = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket_protocol)

    while True:  
        raw_buffer = sniffer.recvfrom(65535)[0]
        ip_header = IP(raw_buffer[0:20])
        data = raw_buffer[64:]
        if data.decode('utf-8') == secret:
            print(f'{ip_header.src_address} replied to your ping')

   
def sendping(ip,mask,secret):
    s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    s.bind(('192.168.1.99',0))

    icmp_type = 8  
    icmp_code = 0
    icmp_checksum = 0
    icmp_identifier = 0
    icmp_sequence = 0

    rawicmp = struct.pack('BBHHH',icmp_type,icmp_code,icmp_checksum,icmp_identifier,icmp_sequence)
    rawicmp = rawicmp + bytes(secret,'utf8')
    
    nettoscan = f'{ip}/{mask}'
    
    for gotip in ipaddress.IPv4Network(nettoscan):
        try:
            s.sendto(rawicmp,(str(gotip),0))        
        except OSError as e:
            print(e)
    
    print('--- All packets sent ---')
           

if __name__ == '__main__':
    
    host = '192.168.1.0'
    mask = '24'

    if len(sys.argv) == 2:
        host = sys.argv[1]
        mask = sys.argv[2]
    
    elif len(sys.argv) == 2:
        host = sys.argv[1] 

    secret = generate_random_hex_string()
    listener = multiprocessing.Process(target=listen,args=(secret,))
    sender = multiprocessing.Process(target=sendping,args=(host,mask,secret))
    try:
        listener.start()
        sender.start()
    except KeyboardInterrupt:
        listener.terminate()
        listener.join()
        sender.terminate()
        sender.join()
        
        


