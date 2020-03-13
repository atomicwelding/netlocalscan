""" scanning machines connected to the local network
    ; by weld
"""

import struct
import binascii

import socket
import netifaces

import time
import threading


_host = {
    'interface':'',
    'mac':'',
    'addr':'',
    'mask':'',
    'netaddr':'',
    'bcaddr':''
}


class Host:
    # constructor
    def __init__(self):
        self.interface  = ''
        self.mac        = ''
        self.addr       = ''
        self.mask       = ''
        self.netaddr    = ''
        self.bcaddr     = ''
    
    # set interface, mac, local ip address, mask, ip of the local network, broadcast adress
    def set_host(self):
        for i in netifaces.interfaces():
            interface = netifaces.ifaddresses(i)
            if netifaces.AF_INET in interface and netifaces.AF_LINK in interface and \
                '127.0.0.1' != interface[netifaces.AF_INET][0]['addr']:
                self.interface   = i
                self.mac         = interface[netifaces.AF_LINK][0]['addr']
                self.addr        = interface[netifaces.AF_INET][0]['addr']
                self.mask        = interface[netifaces.AF_INET][0]['netmask']
                self.netaddr     = self.set_netaddr(self.addr, self.mask)
                self.bcaddr      = self.set_broadcastaddr(self.netaddr, self.mask)
    
    # return network's address
    def set_netaddr(self, addr, mask):
        addr    = addr.split('.')
        mask    = mask.split('.')
        netaddr = ''
        for i in range(len(addr)):
            netaddr = netaddr + str( int(addr[i])&int(mask[i]) ) + '.'
        # delete final '.'
        return netaddr[:-1]
    
    # compute broadcast address
    # pseudo code : broadcast address = (netaddress OR one_complement(mask)) (AND 0xFF) <-- to print it in [0, 255] instead of [-128, 127] 
    def set_broadcastaddr(self, netaddr, mask):
        netaddr       = netaddr.split('.')
        mask          = mask.split('.')
        inverted_mask = list(reversed(mask))
        broadcastaddr = ''
        for i in range(len(netaddr)):
            broadcastaddr = broadcastaddr + str( (int(netaddr[i])|~int(mask[i])) & 0xFF )+'.'
        return broadcastaddr[:-1]

    # print infos
    def print_infos(self):
        print('INTERFACE: ' + self.interface)
        print('MAC: ' + self.mac)
        print('IP: ' + self.addr)
        print('Mask: ' + self.mask)
        print('Network IP: ' + self.netaddr)
        print('Broadcast IP: ' + self.bcaddr) 
        print('==================================')

class Bruteforce:
    # constructor
    def __init__(self):
        self.host = Host()
        self.host.set_host()

        self.arp_payloads = []

    # return raw arp rqt
    # https://en.wikipedia.org/wiki/Address_Resolution_Protocol 
    def craft_arp_payloads(self):
        h_type          = (0x00, 0x01) #2
        p_type          = (0x08, 0x00) #2

        h_addr_length   = (0x06) #1
        p_addr_length   = (0x04) #1

        operation       = (0x00, 0x01) #2

        mac_src         = [int(x, 16) for x in self.host.mac.split(':')]
        ip_src          = [int(x) for x in self.host.addr.split('.')]
        
        mac_dest        = (0xFF,) * 6

        # pseudo code
        # for x in range(MAX_MACHINES_ON_LOCAL):
        #     ip_dest = IP_MACHINE_GENERATED
        #     add STRUCT_ASKING_FOR_THE_IP to ARP_PAYLOADS[]

        # https://en.wikipedia.org/wiki/Classful_network#Classful_addressing_definition
        # it will work, for the very first version, using classful network
        # if 
        #       0 < int(IP.split('.')[0]) < 127      => CLASS A MASK 255.0.0.0 => 255.X.Y.Z
        #       128 < int(IP.split('.')[0]) < 191    => CLASS A MASK 255.255.0.0 => 255.255.Y.Z
        #       192 < int(IP.split('.')[0]) < 223      => CLASS A MASK 255.255.255.0 => 255.255.255.Z
        # 
        # retrieve first ip's parts from local network addr.

        try:
            ip = [int(x) for x in self.host.netaddr.split('.')]
            classful_network = ip[0]
            
            # CLASS A
            if classful_network in range(0, 128):
                for x in range(0, 255):
                    for y in range(1, 255):
                        for z in range(0, 255):
                            ip_dest = [ip[0], x, y, z]
                            self.arp_payloads.append(struct.pack('!28B', *h_type, *p_type, h_addr_length, p_addr_length, *operation, *mac_src, *ip_src, *mac_dest, *ip_dest))

            # CLASS B
            elif classful_network in range(128, 192):
                for y in range(0,255):
                    for z in range(1, 255):
                        ip_dest = [ip[0], ip[1], y, z]
                        self.arp_payloads.append(struct.pack('!28B', *h_type, *p_type, h_addr_length, p_addr_length, *operation, *mac_src, *ip_src, *mac_dest, *ip_dest))
            
            # CLASS C
            elif classful_network in range(192, 223):
                for z in range(1, 255):
                    ip_dest = [ip[0], ip[1], ip[2], z]
                    self.arp_payloads.append(struct.pack('!28B', *h_type, *p_type, h_addr_length, p_addr_length, *operation, *mac_src, *ip_src, *mac_dest, *ip_dest))
            
            # OTHER CLASSES
            else:
                raise ValueError('''This software uses classful network implementation and your actual IP don\'t figure in 
                actual ranges. Please contact author to get help.''')
        except ValueError as err:
            print(err)
    
    # return eth(arp) packets
    # https://en.wikipedia.org/wiki/Ethernet_frame
    def craft_eth_frame(self, payload):
        preamble        = (0xAA,) * 7
        sfd             = 0xAB
        mac_dest        = (0xFF,) * 6
        mac_src         = [int(x, 16) for x in self.host.mac.split(':')]
        ethertype       = 0x0806

        # padding
        if(len(payload) < 46):
            for x in range(46-len(payload)):
                payload = payload + b'\x00'

        interpck_gap    = (0x0,) * 12
        to_checksum     = struct.pack('!12BH%iB' % len(payload), *mac_dest, *mac_src, ethertype, *payload)
        fcs             = binascii.crc32(to_checksum) & 0x7fffffff

        return struct.pack('!12BH%iBI' %len(payload), *mac_dest, *mac_src, ethertype, *payload, fcs)

    # ask every IPs on the network through ARP using RAW sockets
    def start(self):
        self.craft_arp_payloads()
        for payload in self.arp_payloads:
            print(self.craft_eth_frame(payload))
            time.sleep(2)
        

class Server:
    pass

if __name__ == "__main__":
    bruteforce = Bruteforce()
    sender = threading.Thread(target=bruteforce.start)
    sender.start()