# netlocalscan

netlocalscan is a tool that allows you to scan the machine's connected to your local network area. 

It works by bruteforcing IP, using classful network and sending them an ARP request. The software is multithreaded.

The usage requires python3 and netifaces.

## Execution flow

#### Bruteforce
![flow chart](./rsrc/bruteforce_chart.jpg)


#### Serveur
![flow chart 2](./rsrc/listener_server_chart.png)

![schema](./rsrc/schema.png)