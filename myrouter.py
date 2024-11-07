#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
from datetime import datetime

import switchyard
from switchyard.lib.userlib import *
from typing import Dict


# my arpTable class
class ArpTable:
    def __init__(self, exist_time):
        self.dict = {}
        self.exist_time = exist_time

    def add_element(self, ip, mac):
        self.dict[ip] = [mac, datetime.now()]

    def is_ip_in_arp_table(self, ip):
        if ip in self.dict.keys():
            self.dict[ip][1] = datetime.now()
            return self.dict[ip][0]
        return False

    def update_element(self, ip, mac):
        self.dict[ip] = [mac, datetime.now()]

    def refresh(self):
        log_info("arp cache before update:")
        self.print_arc_table()

        new_dict = {}
        for key, value in self.dict.items():
            time_diff = datetime.now() - value[1]
            if time_diff.total_seconds() < self.exist_time:
                new_dict[key] = value
        self.dict = new_dict

        log_info("arp cache after update:")
        self.print_arc_table()

    def print_arc_table(self):
        # dict is empty
        if not self.dict:
            return

        log_info("*********************************************************************")
        for key, value in self.dict.items():
            log_info(f"ip = {key}, mac = {value[0]}, exist_time = {(datetime.now() - value[1]).total_seconds()}")
        log_info("*********************************************************************")


class IPForwardingTable:
    class TableLine:
        def __init__(self, prefix, mask, next_hop, interface):
            self.prefix = prefix
            self.mask = mask
            self.next_hop = next_hop
            self.interface = interface

    def __init__(self):
        self.table = {}
        with open('forwarding_table.txt', 'r') as table_file:
            lines = table_file.readlines()

            for line in lines:
                elements = line.split()

                prefix = elements[0]
                mask = elements[1]
                next_hop = elements[2]
                interface = elements[3]

                prefix_net = IPv4Address(prefix + '/' + mask)

                self.table[prefix_net] = IPForwardingTable.TableLine(prefix, mask, next_hop, interface)

    # match target ip
    def get_match_line(self, target_ip):
        match_lines = []
        for prefix_net in self.table.keys():
            if target_ip in prefix_net:
                match_lines.append(self.table[prefix_net])
        # nothing in match lines
        if not match_lines:
            return None
        # find the max mask
        else:
            max_mask = max(int(line.mask) for line in match_lines)
            for match_line in match_lines:
                if int(match_line.mask) == max_mask:
                    return match_line


class Ipv4PacketWaitingList:
    class ListItem:
        def __init__(self, ipv4_packet, interface, next_hop_ip, arp_request_packet, last_request_time, request_times):
            self.ipv4_packet = ipv4_packet
            self.interface = interface
            self.next_hop_ip = next_hop_ip
            self.arp_request_packet = arp_request_packet
            self.request_interval = last_request_time
            self.request_times = request_times

    def __init__(self, interval_time, max_request_times, router):
        self.interval_time = interval_time
        self.max_request_times = max_request_times
        self.waiting_list = []
        self.router = router

    def add_packet(self, ipv4_packet, interface, next_hop_ip, arp_request_packet, last_request_time, request_times):
        item = Ipv4PacketWaitingList.ListItem(ipv4_packet, interface, next_hop_ip, arp_request_packet,
                                              last_request_time,
                                              request_times)
        self.waiting_list.append(item)

    def refresh(self):
        new_waiting_list = []
        for item in self.waiting_list:
            if (datetime.now() - item.last_request_time).total_seconds() >= self.interval_time:
                # send new arp packet
                if item.request_times < 5:
                    self.router.net.send_packet(item.interface, item.arp_request_packet)
                    item.last_request_time = datetime.now()
                    item.request_times += 1
                    new_waiting_list.append(item)
                # delete item
                else:
                    continue
            else:
                new_waiting_list.append(item)

        self.waiting_list = new_waiting_list

    def get_arp_reply(self, target_ip, target_mac, interface):
        new_waiting_list = []
        for item in self.waiting_list:
            # reply for this item
            if item.next_hop_ip == target_ip and item.interface == interface:
                ethernet_header = Ethernet(src=item.interface.ethaddr, dst=target_mac)
                self.router.net.send_packet(item.interface, ethernet_header + item.ipv4_packet)
            else:
                new_waiting_list.append(item)
        self.waiting_list = new_waiting_list


class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        self.arp_table = ArpTable(100)
        self.forward_table = IPForwardingTable()
        self.ipv4_packet_waiting_list = Ipv4PacketWaitingList(1, 5, self)
        # other initialization stuff here

    def update(self):
        self.arp_table.refresh()
        self.ipv4_packet_waiting_list.refresh()

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        # TODO: your logic here

        # handle arp reply packet
        arp_header = packet.get_header(Arp)
        if arp_header is not None and arp_header.operation == ArpOperation.Reply:
            Router.handle_arp_reply_packet(self, arp_header)

        # handle arp request packet
        arp_header = packet.get_header(Arp)
        if arp_header is not None and arp_header.operation == ArpOperation.Request:
            log_info("receive arp request packet")
            Router.handle_arp_request_packet(self, arp_header, ifaceName, packet)

        # handle IPv4 packet
        ipv4_header = packet.get_header(IPv4)
        ipv4_packet = IPv4()
        if ipv4_header is not None:
            log_info("receive IPv4 packet")
            Router.handle_ipv4_packet(self, ipv4_header, ipv4_packet)

    def handle_arp_reply_packet(self, arp_header):
        sender_ip = arp_header.senderprotoaddr
        sender_mac = arp_header.senderhwaddr
        target_ip = arp_header.targetprotoaddr
        target_mac = arp_header.targethwaddr

        # add ip-mac into arp cache
        if not self.arp_table.is_ip_in_arp_table(sender_ip):
            self.arp_table.add_element(sender_ip, sender_mac)

        if not self.arp_table.is_ip_in_arp_table(target_ip):
            self.arp_table.add_element(target_ip, target_mac)

        # is this arp reply packet for this router?
        for interface in self.net.interfaces():
            if interface.ethaddr == target_mac:
                self.ipv4_packet_waiting_list.get_arp_reply(sender_ip, sender_mac, interface)

    def handle_ipv4_packet(self, ipv4_header, ipv4_packet):
        ipv4_header.ttl -= 1

        forward_table_match_line = self.forward_table.get_match_line(ipv4_header.dst)
        if forward_table_match_line is not None:
            next_hop_ip = forward_table_match_line.next_hop

            # need to send arp request packet
            if not self.arp_table.is_ip_in_arp_table(next_hop_ip):
                interface_name = forward_table_match_line.interface

                for port in self.net.ports:
                    if port.name == interface_name:
                        arp_request_packet = create_ip_arp_request(port.ethaddr,
                                                                   port.ipaddr,
                                                                   next_hop_ip)
                        # self.net.send_packet(port, arp_request_packet)
                        self.ipv4_packet_waiting_list.add_packet(ipv4_packet, port, next_hop_ip, arp_request_packet,
                                                                 datetime.now(), 0)
                        break

    def handle_arp_request_packet(self, arp_header, ifaceName, packet):
        sender_ip = arp_header.senderprotoaddr
        sender_mac = arp_header.senderhwaddr
        target_ip = arp_header.targetprotoaddr
        target_mac = Router.find_mac_by_ip(self, target_ip)

        # add ip-mac into arp cache
        if not self.arp_table.is_ip_in_arp_table(sender_ip):
            self.arp_table.add_element(sender_ip, sender_mac)

        if target_mac is not None and (not self.arp_table.is_ip_in_arp_table(target_ip)):
            self.arp_table.add_element(target_ip, target_mac)

        log_debug(f"target ip = {target_ip}, target mac = {target_mac}")
        # need to replay
        if target_mac is not None:
            log_info("need to reply")
            # create_ip_arp_reply(senderhwaddr, targethwaddr, senderprotoaddr, targetprotoaddr)
            reply_packet = create_ip_arp_reply(target_mac, sender_mac, target_ip, sender_ip)
            log_debug(f"sender ip = {sender_ip}, sender mac = {sender_mac}")

            for interface in self.net.interfaces():
                if interface.name == ifaceName:
                    log_info(f"send arp reply packet {packet} to {interface.name}")
                    self.net.send_packet(interface, reply_packet)

    # my function: ip to mac
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
                recv = self.net.recv_packet(timeout=1.0)
                self.update()
            except NoPackets:
                continue
            except Shutdown:
                break

            self.handle_packet(recv)

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
