#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import arpTable
import ipForwardingTable
import waitingList

import switchyard
from switchyard.lib.userlib import *


class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        self.arp_table = arpTable.ArpTable(100)
        self.forward_table = ipForwardingTable.IPForwardingTable(self)
        self.ipv4_packet_waiting_list = waitingList.Ipv4PacketWaitingList(1, 5, self)
        self.send_packet_log = []
        # other initialization stuff here

        log_info("=============================(router ports)===================")
        for port in self.net.ports():
            log_info(f"ip = {port.ipaddr}, mac = {port.ethaddr}, name = {port.name}")
        log_info("=============================(router ports)===================")

    def router_send_packet(self, interface, send_packet):
        self.send_packet_log.append([interface, send_packet])
        self.net.send_packet(interface, send_packet)

    def update(self):
        # log_info("update")
        self.arp_table.refresh()
        self.ipv4_packet_waiting_list.refresh()

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv

        # TODO: your logic here

        log_info("!!#########################receive packet")
        log_info(f"{packet} arrived on {ifaceName}")

        # packet not for this port
        ethernet_header = packet.get_header(Ethernet)
        if ethernet_header.dst not in [port.ethaddr for port in self.net.ports() if port.name == ifaceName] and str(
                ethernet_header.dst) != 'ff:ff:ff:ff:ff:ff':
            log_info("packet not for this router")
            return

        vlan_header = packet.get_header(Vlan)
        if vlan_header is not None:
            return

        # handle arp reply packet
        arp_header = packet.get_header(Arp)
        if arp_header is not None and arp_header.operation == ArpOperation.Reply:
            log_info("!!###########(receive arp reply packet) ")
            Router.handle_arp_reply_packet(self, arp_header, ethernet_header)

        # handle arp request packet
        arp_header = packet.get_header(Arp)
        if arp_header is not None and arp_header.operation == ArpOperation.Request:
            log_info("??###########(receive arp request packet)")
            Router.handle_arp_request_packet(self, arp_header, ifaceName, packet)

        # handle IPv4 packet
        ipv4_header = packet.get_header(IPv4)
        if ipv4_header is not None:
            log_info("##############(receive ipv4 packet)")
            log_info(f"{packet}")
            Router.handle_ipv4_packet(self, ipv4_header, packet)

    def handle_arp_reply_packet(self, arp_header, ethernet_header):

        if str(ethernet_header.src) == 'ff:ff:ff:ff:ff:ff':
            log_info("illegal arp reply packet")
            return

        sender_ip = arp_header.senderprotoaddr
        sender_mac = arp_header.senderhwaddr
        target_ip = arp_header.targetprotoaddr
        target_mac = arp_header.targethwaddr
        log_info(f"sender ip={sender_ip}, sender_mac={sender_mac}, target ip={target_ip}, target mac={target_mac}")

        # check arp header
        if target_ip not in [port.ipaddr for port in self.net.ports()] or target_mac not in [port.ethaddr for port in
                                                                                             self.net.ports()]:
            log_info("arp reply packet not for this router")
            return

        # add ip-mac into arp cache

        self.arp_table.add_element(sender_ip, sender_mac)

        # if not self.arp_table.is_ip_in_arp_table(target_ip):
        #     log_info("add target ip-mac to arp cache")
        #     self.arp_table.add_element(target_ip, target_mac)

        # is this arp reply packet for this router?
        for interface in self.net.interfaces():
            if interface.ethaddr == target_mac:
                self.ipv4_packet_waiting_list.get_arp_reply(str(sender_ip), sender_mac, interface)

    def handle_ipv4_packet(self, ipv4_header, packet):
        # packet for router itself
        for port in self.net.ports():
            if str(port.ipaddr) == str(ipv4_header.dst):
                log_info("this packet is for router")
                return

        if ipv4_header is not None:
            ipv4_header.ttl -= 1
            log_info(f"ttl = {ipv4_header.ttl}")

        # if dst is in this router, ignore it
        if ipv4_header.dst in [port.ipaddr for port in self.net.ports()]:
            return

        # pdb.set_trace()

        forward_table_match_line = self.forward_table.get_match_line(ipv4_header.dst)
        log_info(f"dest ip = {ipv4_header.dst}")
        if forward_table_match_line is not None:
            next_hop_ip = forward_table_match_line.next_hop
            log_info(f"next hop = {next_hop_ip}")
            if str(next_hop_ip) == '0.0.0.0':
                next_hop_ip = ipv4_header.dst

            interface_name = forward_table_match_line.interface
            log_info(f"interface's name = {interface_name}")

            # need to send arp request packet
            if not self.arp_table.is_ip_in_arp_table(next_hop_ip):
                for port in self.net.ports():
                    # log_info(f"port's name = {port.name}")
                    if port.name == interface_name:
                        # delete ethernet header
                        del packet[0]
                        self.ipv4_packet_waiting_list.add_packet(packet, port, str(next_hop_ip))
                        break
            #
            else:
                log_info("ip-mac in arp cache")
                target_mac = self.arp_table.is_ip_in_arp_table(next_hop_ip)
                for port in self.net.ports():
                    if port.name == interface_name:
                        ethernet_header = Ethernet(src=port.ethaddr, dst=target_mac)
                        del packet[0]
                        log_info(f"packet = {packet}")
                        log_info(f"ethernet_header = {ethernet_header}")
                        packet.prepend_header(ethernet_header)

                        log_info("***********************************(send Ipv4 packet)")
                        log_info(f"new packet = {packet}")

                        self.router_send_packet(port, packet)

    def handle_arp_request_packet(self, arp_header, ifaceName, packet):

        sender_ip = arp_header.senderprotoaddr
        sender_mac = arp_header.senderhwaddr
        target_ip = arp_header.targetprotoaddr
        target_mac = Router.find_mac_by_ip(self, target_ip)
        log_info(f"sender ip={sender_ip}, sender_mac={sender_mac}, target ip={target_ip}, target mac={target_mac}")

        # check arp header
        if target_ip not in [port.ipaddr for port in self.net.ports()]:
            log_info("arp request packet's target ip not in this router")
            return

        # add ip-mac into arp cache
        self.arp_table.add_element(sender_ip, sender_mac)

        # if target_mac is not None and (not self.arp_table.is_ip_in_arp_table(target_ip)):
        #    self.arp_table.add_element(target_ip, target_mac)

        # log_debug(f"target ip = {target_ip}, target mac = {target_mac}")

        # need to replay
        if target_mac is not None:
            log_info("need to reply")
            # create_ip_arp_reply(senderhwaddr, targethwaddr, senderprotoaddr, targetprotoaddr)
            reply_packet = create_ip_arp_reply(target_mac, sender_mac, target_ip, sender_ip)
            log_debug(f"sender ip = {sender_ip}, sender mac = {sender_mac}")

            for interface in self.net.interfaces():
                if interface.name == ifaceName:
                    log_info(f"send arp reply packet to {sender_ip} from {interface.name}")
                    self.router_send_packet(interface, reply_packet)

    # my function: ip to mac in router ports
    def find_mac_by_ip(self, target_ip):
        for port in self.net.ports():
            if port.ipaddr == target_ip:
                return port.ethaddr
        return None

    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            try:
                self.update()
                recv = self.net.recv_packet(timeout=1.0)
                # self.update()
            except NoPackets:
                continue
            except Shutdown:
                break
            # self.update()
            self.handle_packet(recv)
            # self.update()

        self.stop()

    def stop(self):
        self.net.shutdown()


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    router = Router(net)
    router.start()
