from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import in_proto
from ryu.lib.packet import ipv4
from ryu.lib import snortlib
#from handles_honeypot import create_honeypots, stop_honeypots
import socket
import array

HOST = "172.17.0.2"
PORT = 51234

IP_TO_MAC_TABLE = {}
DEFAUT_TABLE = 0
FILTER_TABLE = 5
FORWARD_TABLE = 10

class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'snortlib': snortlib.SnortLib}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.cid = 0
        self.mac_to_port = {}
        self.datapath = None
        self.number_honeypot = None

        self.snort = kwargs['snortlib']
        socket_config = {'unixsock': False}
        self.snort.set_config(socket_config)
        self.snort.start_socket_server()

        # s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # s.bind((HOST, PORT))
        # s.listen(5)
        # conn, addr = s.accept()
        # print(addr)
        # if conn:
        #     print("Connected by ", addr)
        #     while True:
        #         data = conn.recv(1024)
        #         if not data:
        #             break
        #         self.number_honeypot = data.encode("utf8")
        #         create_honeypots(self.number_honeypot)
        #         update_ip_to_mac_tables()
                
        #         print("Number: ", self.number_honeypot)


    def add_filter_table(self, datapath):
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionGotoTable(FILTER_TABLE)]
        mod = parser.OFPFlowMod(datapath=datapath, table_id=DEFAUT_TABLE, instructions=inst)
        datapath.send_msg(mod)

    def add_forward_table(self, datapath):
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionGotoTable(FORWARD_TABLE)]
        mod = parser.OFPFlowMod(datapath=datapath, table_id=FILTER_TABLE, instructions=inst, priority=0)
        datapath.send_msg(mod)

    def packet_redirect(self, msg):
        datapath = self.datapath

        if datapath is None:
            self.logger.info('no switch detected yet, ignoring alert...')
            return

        pkt = packet.Packet(array.array('B', msg.pkt))
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        src_ip = pkt_ipv4.src if pkt_ipv4 else ""
        dst_ip = pkt_ipv4.dst if pkt_ipv4 else ""

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        #self.logger.info("Switch %s: %s ==> %s", datapath.id, src_ip, dst_ip)
        #self.logger.info("IP_TO_MAC_TABLE: %s", IP_TO_MAC_TABLE)
        # self.logger.info("MAC TO PORT: %s", self.mac_to_port )
        # Install flow entry to send packets from port 2 to port 4

        if datapath.id == 2:
            if dst_ip == "10.0.0.10" or dst_ip == "10.0.0.11":
                target_ip = "10.0.0.14"
                actions_01 = [
                    parser.OFPActionSetField(eth_dst=IP_TO_MAC_TABLE[target_ip]),
                    parser.OFPActionSetField(ipv4_dst=target_ip),
                    parser.OFPActionOutput(port=4)]
                actions_02 = [
                    parser.OFPActionSetField(eth_src=IP_TO_MAC_TABLE[dst_ip]),
                    parser.OFPActionSetField(ipv4_src=dst_ip),
                    parser.OFPActionOutput(port=2)]

                self.logger.info("Starting add flow to filer tables action 1")
                match_01 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                           ip_proto=in_proto.IPPROTO_ICMP,
                                           in_port=2, eth_src=IP_TO_MAC_TABLE[src_ip])
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions_01)]
                mod_01 = parser.OFPFlowMod(datapath=datapath, table_id=FILTER_TABLE,
                                        priority=15, match=match_01, idle_timeout=60,
                                        hard_timeout=120, instructions = inst)
                datapath.send_msg(mod_01)

                self.logger.info("Starting add flow to filer tables action 2")
                match_02 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                           ip_proto=in_proto.IPPROTO_ICMP,
                                           in_port=4, eth_src=IP_TO_MAC_TABLE[target_ip])
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions_02)]
                mod_02 = parser.OFPFlowMod(datapath=datapath, table_id=FILTER_TABLE,
                                        priority=15, match=match_02, idle_timeout=60,
                                        hard_timeout=120, instructions = inst)
                datapath.send_msg(mod_02)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        # adding default tables in the startup
        self.add_filter_table(datapath)
        self.add_forward_table(datapath)


    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle=0, hard=0, table_id=FORWARD_TABLE):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    idle_timeout=idle, hard_timeout=hard,
                                    priority=priority, match=match,
                                    instructions=inst, table_id=table_id)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, idle_timeout=idle,
                                    hard_timeout=hard, instructions=inst,
                                    table_id=table_id)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        self.datapath = datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)

        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)

        if pkt_ethernet.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        eth_dst = pkt_ethernet.dst
        eth_src = pkt_ethernet.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        src_ip = pkt_ipv4.src if pkt_ipv4 else ""
        dst_ip = pkt_ipv4.dst if pkt_ipv4 else ""

        if pkt_ipv4:
            if src_ip not in IP_TO_MAC_TABLE:
                IP_TO_MAC_TABLE[src_ip] = eth_src
            elif src_ip in IP_TO_MAC_TABLE and IP_TO_MAC_TABLE[src_ip] != eth_src:
                IP_TO_MAC_TABLE[src_ip] = eth_src
        if pkt_ipv4:
            if dst_ip not in IP_TO_MAC_TABLE:
                IP_TO_MAC_TABLE[dst_ip] = eth_dst
            elif dst_ip in IP_TO_MAC_TABLE and IP_TO_MAC_TABLE[dst_ip] != eth_dst:
                IP_TO_MAC_TABLE[dst_ip] = eth_dst

        self.logger.info("Packet in switch %s - in port %s: %s %s ==> %s %s", dpid, in_port, src_ip, eth_src, dst_ip, eth_dst)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][eth_src] = in_port

        if eth_dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][eth_dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        if datapath.id == 2:
            actions = [parser.OFPActionOutput(out_port), parser.OFPActionOutput(1)]

        else:
            actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth_dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id ,idle=30, hard=30)
                return
            else:
                self.add_flow(datapath, 1, match, actions, idle=30, hard=30)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(snortlib.EventAlert, MAIN_DISPATCHER)
    def process_snort_alert(self, ev):
        msg = ev.msg
        self.dump_alert(ev)
        self.packet_redirect(msg)

    def dump_alert(self, ev):
        self.cid += 1
        msg = ev.msg
        #pkt = packet.Packet(msg.data)
        pkt = packet.Packet(array.array('B', msg.pkt))

        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)


        src_ip = pkt_ipv4.src if pkt_ipv4 else ""
        dst_ip = pkt_ipv4.dst if pkt_ipv4 else ""
        src_mac = pkt_ethernet.src
        dst_mac = pkt_ethernet.dst

        alertmsg = ''.join(msg.alertmsg)
        self.logger.info('Received {0} alert'.format(self.cid))
        self.logger.info("Alert - %s: %s %s ==>> %s %s", alertmsg, src_ip, src_mac, dst_ip, dst_mac)
