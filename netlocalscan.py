""" scanning machines connected to the local network
    ; by weld
"""

import struct
import binascii

import socket
import netifaces


_host = {
    'interface':'',
    'mac':'',
    'addr':'',
    'mask':'',
    'netaddr':'',
    'bcaddr':''
}

# set interface, local ip address, ip of the network, broadcast ip subnetwork mask
def set_host(host):
    for i in netifaces.interfaces():
        interface = netifaces.ifaddresses(i)
        if netifaces.AF_INET in list(interface.keys()) and '127.0.0.1' != interface[netifaces.AF_INET][0]['addr']:
            host['interface']   = i
            host['mac']         = interface[netifaces.AF_LINK][0]['addr']
            host['addr']        = interface[netifaces.AF_INET][0]['addr']
            host['mask']        = interface[netifaces.AF_INET][0]['netmask']
            host['netaddr']     = get_netaddr(host['addr'], host['mask'])
            host['bcaddr']      = get_broadcastaddr(host['netaddr'], host['mask'])

# return network's address
def get_netaddr(addr, mask):
    addr    = addr.split('.')
    mask    = mask.split('.')
    netaddr = ''
    for i in range(len(addr)):
        netaddr = netaddr + str( int(addr[i])&int(mask[i]) ) + '.'
    # delete final '.'
    return netaddr[:-1]

# compute broadcast address
# pseudo code : broadcast address = (netaddress OR one_complement(mask)) (AND 0xFF) <-- to print it in [0, 255] instead of [-128, 127] 
def get_broadcastaddr(netaddr, mask):
    netaddr       = netaddr.split('.')
    mask          = mask.split('.')
    inverted_mask = list(reversed(mask))
    broadcastaddr = ''
    for i in range(len(netaddr)):
        broadcastaddr = broadcastaddr + str( (int(netaddr[i])|~int(mask[i])) & 0xFF )+'.'
    return broadcastaddr[:-1]
    
def print_infos(host):
    print('INTERFACE: ' + host['interface'])
    print('MAC: ' + host['mac'])
    print('IP: ' + host['addr'])
    print('Mask: ' + host['mask'])
    print('Network IP: ' + host['netaddr'])
    print('Broadcast IP: ' + host['bcaddr']) 
    print('==================================')

def frame_check_sequence(frame):
    raise NotImplementedError

# send eth(arp) packets using RAW sockets
# https://tools.ietf.org/html/rfc826
def send_packet(host):
    preamble        = (0xAA,) * 7
    sfd             = 0xAB
    mac_dest        = (0xFF,) * 6
    mac_src         = [int(x, 16) for x in host['mac'].split(':')]
    ethertype       = 0x0806
    payload         = (0xFF,) * 46
    interpck_gap    = (0x0,) * 12
    to_checksum     = struct.pack('!20BH58B', *preamble, sfd, *mac_dest, *mac_src, ethertype, *payload, *interpck_gap)
    fcs             = binascii.crc32(to_checksum)

    eth_pack        = struct.pack('!20BH46Bi12B', *preamble, sfd, *mac_dest, *mac_src, ethertype, *payload, fcs, *interpck_gap)
    
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((host['interface'], 0))

    s.send(eth_pack)

# test
set_host(_host)
send_packet(_host)

# set_host(_host) 
# print_infos(_host)