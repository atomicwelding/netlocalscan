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
        if netifaces.AF_INET in interface and netifaces.AF_LINK in interface and \
                '127.0.0.1' != interface[netifaces.AF_INET][0]['addr']:
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

# return raw arp rqt
# https://en.wikipedia.org/wiki/Address_Resolution_Protocol
def craft_arp_payload(host):
    h_type          = (0x00, 0x01) #2
    p_type          = (0x08, 0x00) #2

    h_addr_length   = (0x06) #1
    p_addr_length   = (0x04) #1

    operation       = (0x00, 0x01) #2

    mac_src         = [int(x, 16) for x in host['mac'].split(':')]
    ip_src          = [int(x) for x in host['addr'].split('.')]
    
    mac_dest        = (0xFF,) * 6
    ip_dest         = [int(x) for x in host['bcaddr'].split('.')]
 
    return struct.pack('!28B', *h_type, *p_type, h_addr_length, p_addr_length, *operation, *mac_src, *ip_src, *mac_dest, *ip_dest)

# send eth(arp) packets using RAW sockets
# https://tools.ietf.org/html/rfc826
def send_packet(host):
    preamble        = (0xAA,) * 7
    sfd             = 0xAB
    mac_dest        = (0xFF,) * 6
    mac_src         = [int(x, 16) for x in host['mac'].split(':')]
    ethertype       = 0x0806
    payload         = craft_arp_payload(host)
    if(len(payload) < 46):
        for x in range(46-len(payload)):
            payload = payload + b'\x00'

    interpck_gap    = (0x0,) * 12
    to_checksum     = struct.pack('!12BH%iB' % len(payload), *mac_dest, *mac_src, ethertype, *payload)
    fcs             = binascii.crc32(to_checksum) & 0x7fffffff

    eth_pack        = struct.pack('!12BH%iBI' %len(payload), *mac_dest, *mac_src, ethertype, *payload, fcs)
    
    print('eth_pack:')
    print(eth_pack)
    
    print('=============')
    
    print('payload:')
    print(payload)

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((host['interface'], 0))

    s.send(eth_pack)

# main
set_host(_host)
print_infos(_host)
send_packet(_host)