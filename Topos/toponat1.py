"""	Topologia 1 Red Taller NAT - Enfasis 3
	Nicolas Zambrano y Sandy Suarez
	Universidad del Cauca - 2022
"""
from mininet.node import Controller, RemoteController, OVSController
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.cli import CLI
from mininet.link import TCLink, Intf
from mininet.log import setLogLevel, info

def TopologyProactive():
    net = Mininet(controller=RemoteController, switch=OVSKernelSwitch, autoSetMacs=True)

    info('*** Adding controller NAT\n')
    c0 = net.addController(name='c0', controller=RemoteController, ip='192.168.56.102', protocol='tcp', port=6653)

    info('*** Add host\n')
    h1 = net.addHost('h1')
    h2 = net.addHost('h2')

    info('*** Add switches\n')
    sw1 = net.addSwitch('s1')
    sw2 = net.addSwitch('s2')
    # Realizando conexiones
    net.addLink( h1, sw1 )

    net.addLink( sw1, sw2 )
    
    net.addLink( h2, sw2 )


    net.build()
    c0.start
    info('***Starting switches\n')
    net.get('s1').start([c0])
    net.get('s2').start([c0])
 
    info('***Post configure switches and hosts\n')
    net.start()
    #net.pingAll()
    info('***Setting up IP and GW of external host\n')
    h2.setIP('30.0.0.1')
    h2.cmd('route add default gw 30.0.0.1')
    info('***Setting up GW of internal host\n')
    h1.cmd('route add default gw 10.0.0.1')
    
    info('***Pinging all hosts to inicializate ARP tables\n')
    net.pingAll(timeout=0.1)

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    TopologyProactive()
