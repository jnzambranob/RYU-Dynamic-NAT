# Dynamic NAT implementation
# Authors:
# -Sandy Tatiana Suarez
# -Jose Nicolas Zambrano
# This is a work for the course of "Applications and Telematic Services" in Universidad del Cauca, Colombia, 2022
# Third party code used:
# L2Learning license:
# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ipaddress import IPv4Address, ip_address
import ipaddress
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.lib.packet import ether_types
import IPy
import ipaddress


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.arp_table = {}  # table storing the match between ip and mac
        self.ip_inside_list = IPy.IP('10.0.0.0/24')  # list of possible hosts inside of the nat (LOCALS)
        self.ip_outside_list = IPy.IP('20.0.0.0/24') # subnet for last host which is located outside of the nat (EXTERNAL)
        self.ip_nat_list = IPy.IP('30.0.0.0/24') # subnet for last host which is located outside of the nat (EXTERNAL)
        self.ip_nat = IPy.IP('30.0.0.1') # IP for last host which is located outside of the nat (EXTERNAL)
        self.ip_nat_str = ipaddress.ip_address(self.ip_nat.strNormal(0)) # changing type of ipaddress for aritmethical operations
        self.ip_inside = ipaddress.ip_address(self.ip_inside_list.strNormal(0)) # changing type of ipaddress for aritmethical operations
        self.ip_outside = ipaddress.ip_address(self.ip_outside_list.strNormal(0)) # changing type of ipaddress for aritmethical operations
        self.ipdiff = int(self.ip_outside)-int(self.ip_inside)
        self.mac_wan= 'ff:ff:ff:ff:ff:ff'

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

        #packet handler for address translation
    #@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler_dynat(self, ev):

        print('PAQUETE EN NAT')
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        arpobj = pkt.get_protocol(arp.arp)
        ipobj = pkt.get_protocol(ipv4.ipv4)
        #ipobjs = pkt.get_protocols(ipv4.ipv4)
        #ipsrc=ipobj.src
        #ipdst=ipobj.dst

        dpid = datapath.id


        if in_port==1:

            print('Entro por Puerto 1-RED LOCAL')
            print(src,",-MAC->",dst)
            #print(ipobj)
            if arpobj:
                if arpobj.dst_ip in self.ip_inside_list: #verification that the arp request is for access a remote host, otherwise, discard ARP request
                    return
                else:
                    self.arp_local(arpobj,datapath)
                    return
            elif ipobj:
                self.ip_local(ipobj,datapath,msg.data)
                return
            else:
                print('No se reconoce el tipo de paquete ingresado por el puerto 1')


        elif in_port==2:
            print('Entro por Puerto 2-RED EXTERNA')
            print(src,",-MAC->",dst)
            if arpobj:
                self.arp_external(arpobj,datapath)
                return
            elif ipobj:
                self.ip_external(ipobj,datapath,msg.data)
                return
            else:
                print('No se reconoce el tipo de paquete ingresado por el puerto 2')
        
        else:
            print('Puerto de entrada no reconocido')



    def _packet_in_handler_l2learning(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        print('PAQUETE EN L2LEARNING')

        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
        print("Paquete Enviado al puerto: %s" % out_port)
        return

    
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        print('\n---PAQUETE ENTRANTE---')
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id

        if dpid==1:
            print ('SWITCH 1 (L2LEARNING)')
            self._packet_in_handler_l2learning(ev)
            return
        elif dpid==2:
            print('SWITCH 2 (NAT)- DPID: ', dpid)
            self._packet_in_handler_dynat(ev)
            return

        else:
            print('SWITCH DPID: %i NO RECONOCIDO - PKT DESCARTADO', dpid)
            return
        

    def packet_sender(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions, data=data)
        #self.logger.info(
        #    "DEBUG: Enviando Paquete: %s\n", data)
        datapath.send_msg(out)
        return

    def arp_local(self, arpobj, datapath):
        if arpobj.src_ip not in self.arp_table:
            print('1')
        self.arp_table[arpobj.src_ip] = arpobj.src_mac

        if arpobj.opcode == arp.ARP_REQUEST:
            print(arpobj.src_ip,"--ARP->",arpobj.dst_ip)
            # If the router received ARP request from a host for a IP in outside network,
            # it will pretend to be that host and give it's own MAC address (ARP Proxy)
            # pretend to be that host and give it's own MAC address (ARP Proxy)
            if arpobj.src_ip in self.ip_inside_list:
                arp_resp = packet.Packet()
                # router maintains two ports, one for each network. '1' is for the network
                # in which hosts h1, h2 and h3 are and '2' is for the network in which host
                # h4 is. For replying to the ARP Request received from the either of
                # h1, h2 or h3, router will use the MAC address corresponding to the port and '1'
                eth_resp = ethernet.ethernet(ethertype=ether_types.ETH_TYPE_ARP,
                                            dst=arpobj.src_mac,
                                            src=datapath.ports[1].hw_addr)

                arp_resp_pkt = arp.arp(opcode=arp.ARP_REPLY,
                                      src_mac=datapath.ports[1].hw_addr,
                                      src_ip=arpobj.dst_ip,
                                      dst_mac=arpobj.src_mac,
                                      dst_ip=arpobj.src_ip)

                arp_resp.add_protocol(eth_resp)
                arp_resp.add_protocol(arp_resp_pkt)
                print('Enviando Respuesta ARP al host interno')
                self.packet_sender(datapath, 1, arp_resp)
                return


    def arp_external(self, arpobj, datapath):
        if arpobj.src_ip in self.ip_nat_list:

            self.mac_wan=arpobj.src_mac #save the mac of the wan host

            arp_reply = packet.Packet()
            # NAT controller sends the arp to the external host own table
            reply_eth_pkt = ethernet.ethernet(ethertype=ether_types.ETH_TYPE_ARP,
                                              dst=arpobj.src_mac,
                                              src=datapath.ports[2].hw_addr)

            reply_arp_pkt = arp.arp(opcode=arp.ARP_REPLY,
                                    src_mac=datapath.ports[2].hw_addr,
                                    src_ip=arpobj.dst_ip,
                                    dst_mac=arpobj.src_mac,
                                    dst_ip=arpobj.src_ip)

            arp_reply.add_protocol(reply_eth_pkt)
            arp_reply.add_protocol(reply_arp_pkt)
            print('Enviando Respuesta ARP al host externo')
            self.packet_sender(datapath, 2, arp_reply)
            return

    def ip_local(self, ipobj, datapath, dataorg):
        print("TRADUCIENDO PAQUETE IP RECIBIDO DEL PUERTO LOCAL: \n",ipobj)
        
        ip_src_internal=ipaddress.ip_address(ipobj.src)
        ip_nated=str(ip_src_internal+self.ipdiff)


        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        data = None
        data = dataorg

        actions_local = [parser.OFPActionSetField(eth_src=datapath.ports[2].hw_addr),
                   parser.OFPActionSetField(eth_dst=self.mac_wan),
                   parser.OFPActionSetField(ipv4_src=ip_nated),
                   parser.OFPActionOutput(port=2),]

        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions_local, data=data)
        #self.logger.info(
        #    "DEBUG: Enviando Paquete: %s\n", data)

        #pkt = packet.Packet(out)
        #ipobj_out = pkt.get_protocol(ipv4.ipv4)
        print("PAQUETE TRADUCIDO SALIENTE: \n",out)

        datapath.send_msg(out)
        return

    def ip_external(self, ipobj, datapath, dataorg):
        print("TRADUCIENDO PAQUETE IP RECIBIDO DEL PUERTO EXTERNO: \n",ipobj)
        ip_src_external=ipaddress.ip_address(ipobj.dst)
        ip_denated=str(ip_src_external-self.ipdiff)


        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        data = None
        data = dataorg

        actions_ext = [parser.OFPActionSetField(eth_src=datapath.ports[1].hw_addr),
                   parser.OFPActionSetField(eth_dst=self.arp_table[ip_denated]),
                   parser.OFPActionSetField(ipv4_dst=ip_denated),
                   parser.OFPActionOutput(port=1),]

        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions_ext, data=data)
        #self.logger.info(
        #    "DEBUG: Enviando Paquete: %s\n", data)

        #pkt = packet.Packet(out)
        #ipobj_out = pkt.get_protocol(ipv4.ipv4)
        print("PAQUETE TRADUCIDO SALIENTE: \n",out)

        datapath.send_msg(out)
        return