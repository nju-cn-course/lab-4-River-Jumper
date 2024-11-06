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
            return True
        return False

    def update_element(self, ip, mac):
        self.dict[ip] = [mac, datetime.now()]

    def delete_element_out_of_time(self):
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
        def __init__(self, prefix, mask, dest_addr, interface):
            self.prefix = prefix
            self.mask = mask
            self.dest_addr = dest_addr
            self.interface = interface

    def __init__(self):
        self.table = {}
        with open('forwarding_table.txt', 'r') as table_file:
            lines = table_file.readlines()

            for line in lines:
                elements = line.split()

                prefix = elements[0]
                mask = elements[1]
                dest_addr = elements[2]
                interface = elements[3]

                prefix_net = IPv4Address(prefix + '/' + mask)

                self.table[prefix_net] = IPForwardingTable.TableLine(prefix, mask, dest_addr, interface)

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
            longest_match_line = max(int(line.mask) for line in match_lines)
            return longest_match_line


class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        self.arp_cache = ArpTable(100)
        self.forward_table = IPForwardingTable()
        # other initialization stuff here

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        # TODO: your logic here
        # handle arp packet
        Router.handle_arp_packet(self, ifaceName, packet)
        # handle other packet

    def handle_arp_packet(self, ifaceName, packet):
        arp = packet.get_header(Arp)
        if arp is not None:
            log_info("receive arp packet")

            sender_ip = arp.senderprotoaddr
            sender_mac = arp.senderhwaddr
            target_ip = arp.targetprotoaddr
            target_mac = Router.find_mac_by_ip(self, target_ip)

            # update arp cache
            self.arp_cache.delete_element_out_of_time()

            # add ip-mac into arp cache
            if not self.arp_cache.is_ip_in_arp_table(sender_ip):
                self.arp_cache.add_element(sender_ip, sender_mac)

            if target_mac is not None and (not self.arp_cache.is_ip_in_arp_table(target_ip)):
                self.arp_cache.add_element(target_ip, target_mac)

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
