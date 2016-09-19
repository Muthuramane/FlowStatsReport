#!/usr/bin/python
# -*- coding: iso-8859-15 -*-
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

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4 
from ryu.lib.packet import ether_types
from ryu.lib import hub
import os
from time import time


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.mac_to_ip = {}
        self.ip_to_mac = {}
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.dpFileHandle = open("BigDataFlowStats.log", "w")
        self.dpFileHandle.close()

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

	
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev): 
		datapath = ev.datapath
		if ev.state == MAIN_DISPATCHER:
			if not datapath.id in self.datapaths:
				self.logger.debug("register datapath: %016x", datapath.id)
				self.datapaths[datapath.id] = datapath
		elif ev.state == DEAD_DISPATCHER:
			if datapath.id in self.datapaths:
				self.logger.debug("unregister datapath: %016x", datapath.id) 
				del self.datapaths[datapath.id]

    def _monitor(self): 
		while True:
			for dp in self.datapaths.values(): 
				self._request_stats(dp)
			hub.sleep(10)

    def _request_stats(self, datapath):
		self.logger.debug("send stats request: %016x", datapath.id) 
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		req = parser.OFPFlowStatsRequest(datapath)
		datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER) 
    def _flow_stats_reply_handler(self, ev):
		body = ev.msg.body
		dpid = ev.msg.datapath.id
		self.dpFileHandle = open("BigDataFlowStats.log", "a")
		self.logger.info("datapath         "
                 "in-port  eth-dst"
                 "out-port packets  bytes")

		self.logger.info("---------------- ")

		for flow in body:
			if flow.priority == 1: 
				self.logger.info("DP: %016x I: %8x EDst: %17s ESrc: %17s Ins: %8x", ev.msg.datapath.id,
					flow.match['in_port'], flow.match['eth_dst'], flow.match['eth_src'],
					flow.instructions[0].actions[0].port)
				self.logger.info("PCnt: %8x BCnt: %8d", flow.packet_count, flow.byte_count)
				t = time()
				dst = flow.match['eth_dst']
				src = flow.match['eth_src']
				if dpid in self.mac_to_ip:
					if src in self.mac_to_ip[dpid]:
						srcIP = self.mac_to_ip[dpid][src]
					else:
						srcIP = "0.0.0.0"

					if dst in self.mac_to_ip[dpid]:
						dstIP = self.mac_to_ip[dpid][dst]
					else:
						dstIP = "0.0.0.0"

					self.dpFileHandle.write("".join("%f,%x,%x,%s,%s,%s,%s,%x,%x\n"%(t,dpid,
						flow.match['in_port'], dst, src, srcIP, dstIP, flow.packet_count,flow.byte_count)))
		
		self.dpFileHandle.close()
	
#        for stat in sorted([flow for flow in body if flow.priority == 1], key=lambda flow: (flow.match[’in_port’], flow.match[’eth_dst’])):
#            self.logger.info(’%016x %8x %17s %8x %8d %8d’, 
#					ev.msg.datapath.id,
#					stat.match[’in_port’],
#					stat.match[’eth_dst’],
#					stat.instructions[0].actions[0].port,
#					stat.packet_count,
#					stat.byte_count)




    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
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
        self.ip_to_mac.setdefault(dpid, {})
        self.mac_to_ip.setdefault(dpid, {})

        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ipV4 = pkt.get_protocols(ipv4.ipv4)[0]
            srcIP = ipV4.src
            dstIP = ipV4.dst
            self.mac_to_ip[dpid][src] = srcIP
            self.mac_to_ip[dpid][dst] = dstIP
            self.ip_to_mac[dpid][srcIP] = src
            self.ip_to_mac[dpid][dstIP] = dst
            self.logger.info("PacketIn:  S.IP: %s D.IP: %s\n", srcIP, dstIP)
        
        self.logger.info("PacketIn: DPID: %s Src: %s Dst: %s In: %s\n", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            #match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
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
