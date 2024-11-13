#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''
import copy

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
        self.receive_packet_log = []
        self.handlers = [
            (self.is_ipv4_packet, self.handle_ipv4_packet),
            (self.is_arp_request_packet, self.handle_arp_request_packet),
            (self.is_arp_reply_packet, self.handle_arp_reply_packet)
        ]
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
        self.receive_packet_log.append([ifaceName, packet])

        # deal with ethernet_header
        # first header is not ethernet header
        ethernet_header = packet[0]
        del packet[0]
        if not isinstance(ethernet_header, Ethernet):
            log_info("first header is not ethernet header")
            return
        # packet not for this port
        if ethernet_header.dst not in [port.ethaddr for port in self.net.ports() if port.name == ifaceName] and str(
                ethernet_header.dst) != 'ff:ff:ff:ff:ff:ff':
            log_info("packet not for this router")
            return

        for condition, handler in self.handlers:
            if condition(packet):
                handler(ifaceName, packet)
            else:
                log_info("No handler in handlers can deal with this packet!")


        '''
        # vlan_header = packet.get_header(Vlan)
        if packet.has_header(Vlan):
            return

        # handle arp reply packet
        arp_header = packet.get_header(Arp)
        if arp_header is not None and arp_header.operation == ArpOperation.Reply:
            log_info("!!###########(receive arp reply packet) ")
            Router.handle_arp_reply_packet(self, ifaceName, packet)

        # handle arp request packet
        arp_header = packet.get_header(Arp)
        if arp_header is not None and arp_header.operation == ArpOperation.Request:
            log_info("??###########(receive arp request packet)")
            Router.handle_arp_request_packet(self, ifaceName, packet)

        # handle IPv4 packet
        ipv4_header = packet.get_header(IPv4)
        if ipv4_header is not None:
            log_info("##############(receive ipv4 packet)")
            Router.handle_ipv4_packet(self, ifaceName, packet)
        '''

    def is_ipv4_packet(self, packet):
        return isinstance(packet[0], IPv4)

    def is_arp_request_packet(self, packet):
        return isinstance(packet[0], Arp) and packet[0].operation == ArpOperation.Request

    def is_arp_reply_packet(self, packet):
        return isinstance(packet[0], Arp) and packet[0].operation == ArpOperation.Reply

    def handle_arp_reply_packet(self, receive_port_name, packet):
        log_info("!!###########(receive arp reply packet) ")

        arp_header = packet.get_header(Arp)

        sender_ip = arp_header.senderprotoaddr
        sender_mac = arp_header.senderhwaddr
        target_ip = arp_header.targetprotoaddr
        target_mac = arp_header.targethwaddr
        log_info(f"sender ip={sender_ip}, sender_mac={sender_mac}, target ip={target_ip}, target mac={target_mac}")

        if str(sender_mac) == 'ff:ff:ff:ff:ff:ff':
            log_info("illegal arp reply packet")
            return

        # check arp header
        if target_ip not in [port.ipaddr for port in self.net.ports()] or target_mac not in [port.ethaddr for port in
                                                                                             self.net.ports()]:
            log_info("arp reply packet not for this router")
            return

        # add ip-mac into arp cache

        self.arp_table.add_element(sender_ip, sender_mac)

        # is this arp reply packet for this router?
        for interface in self.net.interfaces():
            if interface.ethaddr == target_mac:
                self.ipv4_packet_waiting_list.get_arp_reply(str(sender_ip), sender_mac, interface)

    def handle_ipv4_packet(self, receive_port_name, packet):
        log_info("!!###########(receive ipv4 packet) ")
        ipv4_header = packet.get_header(IPv4)
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
                        self.ipv4_packet_waiting_list.add_packet(packet, port, str(next_hop_ip))
                        break
            #
            else:
                log_info("ip-mac in arp cache")
                target_mac = self.arp_table.is_ip_in_arp_table(next_hop_ip)
                for port in self.net.ports():
                    if port.name == interface_name:
                        ethernet_header = Ethernet(src=port.ethaddr, dst=target_mac)
                        log_info(f"packet = {packet}")
                        log_info(f"ethernet_header = {ethernet_header}")
                        packet.prepend_header(ethernet_header)

                        log_info("***********************************(send Ipv4 packet)")
                        log_info(f"new packet = {packet}")

                        self.router_send_packet(port, packet)

    def handle_arp_request_packet(self, receive_port_name, packet):
        log_info("!!###########(receive arp reply packet) ")
        arp_header = packet.get_header(Arp)

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

        # need to replay
        if target_mac is not None:
            log_info("need to reply")
            # create_ip_arp_reply
            reply_packet = create_ip_arp_reply(target_mac, sender_mac, target_ip, sender_ip)
            log_debug(f"sender ip = {sender_ip}, sender mac = {sender_mac}")

            for interface in self.net.interfaces():
                if interface.name == receive_port_name:
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
