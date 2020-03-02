""" scanning machines that are connected to local network
    by weld
"""
import netifaces 

_host = {
    'addr':'',
    'mask':'',
    'netaddr':'',
    'bcaddr':''
}

# set local ip address, ip of the network and subnetwork mask
def set_host():
    for i in netifaces.interfaces():
        interface = netifaces.ifaddresses(i)
        if netifaces.AF_INET in list(interface.keys()) and '127.0.0.1' != interface[netifaces.AF_INET][0]['addr']:
            _host['addr']    = interface[netifaces.AF_INET][0]['addr']
            _host['mask']    = interface[netifaces.AF_INET][0]['netmask']
            _host['netaddr'] = get_netaddr(_host['addr'], _host['mask'])
            _host['bcaddr']  = get_broadcastaddr(_host['netaddr'], _host['mask'])

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
        broadcastaddr = broadcastaddr + str( (int(netaddr[i])|~int(mask[i])) & 0xFF)+'.'
    return broadcastaddr[:-1]
    


# test 
set_host()

