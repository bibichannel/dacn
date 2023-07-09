#!/usr/bin/python

from mininet.net import Containernet
from mininet.node import OVSSwitch, RemoteController
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import info, setLogLevel

setLogLevel('info')

info('*** Create connect remote controller\n')
net = Containernet(waitConnected=True)
c0 = net.addController( name='c0',
                        controller=RemoteController,
                        ip='0.0.0.0',
                        protocol='tcp',
                        port=6633)

info('*** Adding docker containers\n')
d1 = net.addDocker( 'd1', 
                    ip='10.0.0.10', 
                    dimage="bibichannel/ubuntu-trusty:v1")
d2 = net.addDocker( 'd2', 
                    ip='10.0.0.11', 
                    dimage="bibichannel/ubuntu-trusty:v1")
snort = net.addDocker( 'snort', 
                    ip='10.0.0.12', 
                    dimage="meokisama/snort-sdn:v1")
attacker = net.addDocker( 'attacker', 
                    ip='10.0.0.13', 
                    dimage="bibichannel/ubuntu-trusty:v1")
d3 = net.addDocker( 'd3', 
                    ip='10.0.0.14', 
                    dimage="bibichannel/ubuntu-trusty:v1")

info('*** Adding switches\n')
s1 = net.addSwitch('s1')
s2 = net.addSwitch('s2')
s3 = net.addSwitch('s3')

info('*** Creating links\n')
net.addLink(d1, s1)
net.addLink(d2, s1)
net.addLink(snort, s2)
net.addLink(attacker, s2)
net.addLink(d3, s3)
net.addLink(s1, s2, cls=TCLink, delay='100ms', bw=1)
net.addLink(s2, s3, cls=TCLink, delay='100ms', bw=1)

info('*** Starting network\n')
net.start()

info('*** Testing connectivity\n')
net.ping([d1, d2])
net.ping([d1, d3])
net.ping([d2, d3])
net.ping([attacker, d1])
net.ping([attacker, d2])
net.ping([attacker, d3])
net.ping([attacker, snort])

info('*** Running CLI\n')
CLI(net)

info('*** Stopping network')
net.stop()
