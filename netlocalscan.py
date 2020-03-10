""" scanning machines that are connected to local network
    ; by weld
"""

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

# send eth(arp) packets using RAW sockets
# def send_packet(host, dest_ip):

# test
set_host(_host) 
print_infos(_host)