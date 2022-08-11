"""	Topologia 5 Red Taller NAT - Enfasis 3
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
    h3 = net.addHost('h3')
    h4 = net.addHost('h4')
    h5 = net.addHost('h5')
    h6 = net.addHost('h6')
    h7 = net.addHost('h7')
    h8 = net.addHost('h8')
    h9 = net.addHost('h9')
    h10 = net.addHost('h10')
    h11 = net.addHost('h11')

    info('*** Add switches\n')
    sw1 = net.addSwitch('s1')
    sw2 = net.addSwitch('s2')
    # Realizando conexiones
    net.addLink( h1, sw1 )
    net.addLink( h2, sw1 )
    net.addLink( h3, sw1 )
    net.addLink( h4, sw1 )
    net.addLink( h5, sw1 )
    net.addLink( h6, sw1 )
    net.addLink( h7, sw1 )
    net.addLink( h8, sw1 )
    net.addLink( h9, sw1 )
    net.addLink( h10, sw1 )

    net.addLink( sw1, sw2 )

    net.addLink( h11, sw2 )
    
    net.build()
    c0.start
    info('***Starting switches\n')
    net.get('s1').start([c0])
    net.get('s2').start([c0])
 
    info('***Post configure switches and hosts\n')
    net.start()
    #net.pingAll()
    info('***Setting up IP and GW of external host\n')
    h11.setIP('30.0.0.1')
    h11.cmd('route add default gw 30.0.0.1')
    info('***Setting up GW of internal host\n')
    h1.cmd('route add default gw 10.0.0.1')
    h2.cmd('route add default gw 10.0.0.2')
    h3.cmd('route add default gw 10.0.0.3')
    h4.cmd('route add default gw 10.0.0.4')
    h5.cmd('route add default gw 10.0.0.5')
    h6.cmd('route add default gw 10.0.0.6')
    h7.cmd('route add default gw 10.0.0.7')
    h8.cmd('route add default gw 10.0.0.8')
    h9.cmd('route add default gw 10.0.0.9')
    h10.cmd('route add default gw 10.0.0.10')

    info('***Pinging all hosts to inicializate ARP tables\n')
    net.pingAll(timeout=0.1)

    info('***Performing IPERF parallel for testing (10 Seconds)\n')
    h11.cmd('iperf -s -D')
    h1.cmd('iperf -t 10 -c 30.0.0.1 &')
    h2.cmd('iperf -t 10 -c 30.0.0.1 &')
    h3.cmd('iperf -t 10 -c 30.0.0.1 &')
    h4.cmd('iperf -t 10 -c 30.0.0.1 &')
    h5.cmd('iperf -t 10 -c 30.0.0.1 &')
    h6.cmd('iperf -t 10 -c 30.0.0.1 &')
    h7.cmd('iperf -t 10 -c 30.0.0.1 &')
    h8.cmd('iperf -t 10 -c 30.0.0.1 &')
    h9.cmd('iperf -t 10 -c 30.0.0.1 &')
    h10.cmd('iperf -t 10 -c 30.0.0.1 &')

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    TopologyProactive()