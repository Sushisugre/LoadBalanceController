from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
import pox.lib.packet as pkt
import threading

log = core.getLogger()
IDLE_TIMEOUT = 60

class Load_Balancer(object):
    """ Controller as a load balancer """

    def __init__ (self, connection, balancer_addr, server_ips):
        # Keep track of the connection to the switch     
        self.connection = connection
        # This binds our PacketIn event listener
        connection.addListeners(self)
        self.index = 0
        self.flow_map = {}
        self.mac = EthAddr("01:01:01:01:01:01")
        self.ip = IPAddr(balancer_addr)
        self.server_ips = server_ips
        self.servers = []
        self.clients = []
        for server_ip in server_ips:
            self.arp_request(server_ip)
        
    def pick_server(self):
        """
        Pick server in a round robin fasion
        """
        server = self.servers[self.index]
        print "pick ip: " + str(server['ip']) \
                + " mac: "+ str(server['mac']) \
                + " port:" + str(server['port']) 
        self.index = (self.index + 1) % len(self.servers)
        return server;

    def remove_mapping(self, client_mac):
        del self.flow_map[client_mac]


    def resend_packet (self, packet_in, out_port):
        """
        Instructs the switch to resend a packet      
        "packet_in" is the ofp_packet_in object the switch had 
        sent to the controller due to a table-miss.
        """
        msg = of.ofp_packet_out()
        msg.data = packet_in
        action = of.ofp_action_output(port = out_port)
        msg.actions.append(action)
        self.connection.send(msg)

    def arp_request(self, server_ip):
        """
        Broadcast arp to find server MAC address
        """
        log.debug("arp request for "+ str(server_ip))
        packet = pkt.ethernet(
                type = pkt.ethernet.ARP_TYPE,
                src = self.mac,
                dst = pkt.ETHER_BROADCAST)

        packet.payload = pkt.arp(
                opcode = pkt.arp.REQUEST,
                hwtype = pkt.arp.HW_TYPE_ETHERNET,
                prototype = pkt.arp.PROTO_TYPE_IP,
                hwsrc = self.mac,
                protodst = server_ip,
                protosrc = self.ip)

        msg = of.ofp_packet_out(
                data = packet.pack(),
                action = of.ofp_action_output(port = of.OFPP_FLOOD))

        self.connection.send(msg)


    def forward_packet (self, packet_in, out_port):
        """
        Instructs the switch to resend a packet      
        "packet_in" is the ofp_packet_in object the switch had 
        sent to the controller due to a table-miss.
        """
        msg = of.ofp_packet_out()
        msg.data = packet_in
        action = of.ofp_action_output(port = out_port)
        msg.actions.append(action)
        self.connection.send(msg)

    def handle_arp(self, packet, in_port):
        arp = packet.find("arp")
        if packet.payload.opcode == arp.REPLY: # Server or client reply
            if arp.protosrc in self.server_ips:
                log.debug("Server ARP reply :"+ str(arp.hwsrc));
                server = {
                    'ip': arp.protosrc,
                    'mac': arp.hwsrc,
                    'port': in_port
                }
                self.servers.append(server)
            else:
                log.debug("Client ARP reply :"+ str(arp.hwsrc));
                client = {
                    'ip': arp.protosrc,
                    'mac': arp.hwsrc,
                    'port': in_port
                }
                self.clients.append(client)

        elif packet.payload.opcode == arp.REQUEST: # Request for balancer
            log.debug("ARP request for Load balancer");

            packet = pkt.ethernet(
                    type = pkt.ethernet.ARP_TYPE,
                    src = self.mac,
                    dst = arp.hwsrc)
            packet.payload = pkt.arp(
                    opcode = pkt.arp.REPLY,
                    hwtype = pkt.arp.HW_TYPE_ETHERNET,
                    prototype = pkt.arp.PROTO_TYPE_IP,
                    hwsrc = self.mac,
                    hwdst = arp.hwsrc,
                    protosrc = self.ip,
                    protodst = arp.protosrc)
            msg = of.ofp_packet_out(
                    data = packet.pack(),
                    action = of.ofp_action_output(port = in_port))
            self.connection.send(msg)

    def handle_tcp(self, packet, packet_in, inport):
        ip_packet = packet.find('ipv4')
        tcp_seg = ip_packet.find('tcp')

        # server to client
        if ip_packet.srcip in self.server_ips:
            self.handle_server_res(packet_in, packet, tcp_seg)
            return

        # client to server
        self.handle_client_req(packet_in, packet, tcp_seg)

    def handle_server_res(self, packet_in, packet, tcp_seg):
        """
        Change the src address to load balancer's address for consistensy
        """
        actions = []
        # bind to load balancer's address
        actions.append(of.ofp_action_dl_addr.set_src(self.mac))
        actions.append(of.ofp_action_nw_addr.set_src(self.ip))
        actions.append(of.ofp_action_output(port = of.OFPP_NORMAL))
        match = of.ofp_match.from_packet(packet)

        msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                              # data=packet_in,
                              idle_timeout = IDLE_TIMEOUT,
                              hard_timeout = of.OFP_FLOW_PERMANENT,
                              actions=actions,
                              match=match)
        self.connection.send(msg) 

    def handle_client_req(self, packet_in, packet, tcp_seg):
        """
        """
        ip_packet = packet.find('ipv4')
        src_mac = packet.src
        src_ip = ip_packet.srcip

        # flow already registered, not expried yet
        if src_mac in self.flow_map:
            return

        # pick server
        server = self.pick_server()

        # register flow, set expire time
        self.flow_map[src_mac] = server
        threading.Timer(IDLE_TIMEOUT, self.remove_mapping, [src_mac]).start()

        # set address of real server
        actions = []
        # dst mac address
        actions.append(of.ofp_action_dl_addr.set_dst(server['mac']))
        # dst ip address
        actions.append(of.ofp_action_nw_addr.set_dst(server['ip']))
        actions.append(of.ofp_action_output(port = of.OFPP_NORMAL))
        # match = of.ofp_match.from_packet(packet)
        match = of.ofp_match(dl_src=src_mac,
                             dl_dst=self.mac,
                             nw_src=src_ip
                             nw_src=self.ip)

        # install to flow table
        msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                              # data=packet_in,
                              idle_timeout = IDLE_TIMEOUT,
                              hard_timeout = of.OFP_FLOW_PERMANENT,
                              actions=actions,
                              match=match)
        self.connection.send(msg) 
        

    def _handle_PacketIn (self, event):
        packet_in = event.ofp 
        packet = event.parsed
        src_mac = packet.src
        dst_mac = packet.dst
        in_port = event.port

        log.debug("Receive "+ str(packet.type) + " from " + str(src_mac))

        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return
        # handle arp messages
        if packet.type == pkt.ethernet.ARP_TYPE:
            self.handle_arp(packet, in_port)
            return
        # not going to handle it, just resent
        if packet.type != pkt.ethernet.IP_TYPE:
            self.resend_packet(packet_in, of.OFPP_NORMAL)
            return
        # normal tcp/ip packets
        self.handle_tcp(packet, packet_in, in_port)

"""
    Launch load balancer
    balancer: ip address of load balancer
    servers: ip address of servers
"""
def launch (balancer_addr, server_addrs):
    balancer = IPAddr(balancer_addr)
    server_ips = [IPAddr(x) for x in server_addrs.split(",")]
    # servers = {}
    # for server in [IPAddr(x) for x in server_addrs.split(",")]:
    #     servers[server] = None

    def start_switch (event):
        log.debug("Controlling %s" % (event.connection))
        core.registerNew(Load_Balancer,event.connection, balancer, server_ips)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
