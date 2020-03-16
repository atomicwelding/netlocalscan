# netlocalscan

netlocalscan is a tool that allows you to scan the machines' connected to your local network area. 

It works by bruteforcing IP, using classful network and sending them an ARP request. The software is multithreaded.

The usage requires python3 and netifaces.

## Usage

#### Install

```bash
curl -OL --insecure https://github.com/atomicwelding/netlocalscan/archive/master.zip
unzip master.zip
cd ./netlocalscan-master
sudo pip3 install netifaces
sudo python3 ./src/netlocalscan.py
```
You need to run the script as root, since you need those rights to access low-level interfaces.
## Execution flow

#### Bruteforce
![flow chart](./rsrc/bruteforce_chart.jpg)


#### Server
![flow chart 2](./rsrc/listener_server_chart.png)


## ARP
![schema](./rsrc/schema_arp.png)