#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''
import ipaddress
import pdb
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
        log_info(f"Arp tabel: add {ip} to {mac}")
        self.dict[ip] = [mac, datetime.now()]
        self.print_arc_table()

    def is_ip_in_arp_table(self, ip):
        if ip in self.dict.keys():
            self.dict[ip][1] = datetime.now()
            return self.dict[ip][0]
        return False

    def update_element(self, ip, mac):
        self.dict[ip] = [mac, datetime.now()]

    def refresh(self):
        # log_info("arp cache before update:")
        # self.print_arc_table()

        new_dict = {}
        for key, value in self.dict.items():
            time_diff = datetime.now() - value[1]
            if time_diff.total_seconds() < self.exist_time:
                new_dict[key] = value
        self.dict = new_dict

        # log_info("arp cache after update:")
        # self.print_arc_table()

    def print_arc_table(self):
        # dict is empty
        if not self.dict:
            return

        log_info("=========================================================================(arp table)")
        for key, value in self.dict.items():
            log_info(f"ip = {key}, mac = {value[0]}, exist_time = {(datetime.now() - value[1]).total_seconds()}")
        log_info("=========================================================================")


class IPForwardingTable:
    class TableLine:
        def __init__(self, prefix, mask, next_hop, interface):
            self.prefix = prefix
            self.mask = mask
            self.next_hop = next_hop
            self.interface = interface

    def __init__(self, router):
        self.table = {}
        self.router = router

        for port in self.router.net.ports():
            netmask = port.netmask
            ipaddr = port.ipaddr
            prefix = str(ipaddress.IPv4Address(int(ipaddr) & int(netmask)))
            interface_name = port.name

            prefix_net = IPv4Network(prefix + '/' + str(netmask))
            self.table[prefix_net] = IPForwardingTable.TableLine(prefix, str(netmask), '0.0.0.0', str(interface_name))

        with open('forwarding_table.txt', 'r') as table_file:
            lines = table_file.readlines()
            for line in lines:
                elements = line.split()

                prefix = elements[0]
                mask = elements[1]
                next_hop = elements[2]
                interface = elements[3]

                prefix_net = IPv4Network(prefix + '/' + mask)

                self.table[prefix_net] = IPForwardingTable.TableLine(prefix, mask, next_hop, interface)
        log_info("******************************START***************************************")
        for key, value in self.table.items():
            log_info(value.prefix + ' ' + value.mask + ' ' + value.next_hop + ' ' + value.interface)
        log_info("******************************END*****************************************\n")

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
            max_mask = max(int(IPv4Address(line.mask)) for line in match_lines)
            for match_line in match_lines:
                if int(IPv4Address(match_line.mask)) == max_mask:
                    return match_line


class Ipv4PacketWaitingList:
    class ArpRequestMessage:
        def __init__(self, arp_request_packet, interface, last_request_time, request_times):
            self.arp_request_packet = arp_request_packet
            self.interface = interface
            self.last_request_time = last_request_time
            self.request_times = request_times

    def __init__(self, interval_time, max_request_times, router):
        self.interval_time = interval_time
        self.max_request_times = max_request_times
        self.waiting_list = []
        self.router = router
        self.ip2waiting_list = {}
        self.ip2arp_request = {}

    def print_waiting_list(self):
        log_info("----------------------------------------------------(waiting list)")
        for key in self.ip2waiting_list.keys():
            log_info(f"ip:{key}, num:{len(self.ip2waiting_list[key])}, times: {self.ip2arp_request[key].request_times}")
        log_info("----------------------------------------------------")

    def add_packet(self, packet, interface, next_hop_ip):
        log_info(f"Waiting list: add dst({next_hop_ip}) on {interface}")
        if next_hop_ip not in self.ip2waiting_list.keys():
            self.ip2waiting_list[next_hop_ip] = []
            self.ip2waiting_list[next_hop_ip].append(packet)
            log_info(
                f"make arp request packet, sender_mac = {interface.ethaddr}, sender_ip = {interface.ipaddr}, target_ip = {next_hop_ip}")
            arp_request_packet = create_ip_arp_request(interface.ethaddr,
                                                       interface.ipaddr,
                                                       next_hop_ip)
            log_info("****************(send arp request)")
            self.router.router_send_packet(interface, arp_request_packet)
            log_info(
                f"send arp request packet from {interface.name}, router all send packets num:{len(self.router.send_packet_log)}")
            self.ip2arp_request[next_hop_ip] = self.ArpRequestMessage(arp_request_packet, interface,
                                                                      datetime.now(), 1)
        else:
            self.ip2waiting_list[next_hop_ip].append(packet)
        self.print_waiting_list()

    def is_ip_in_waiting_list(self, ip):
        return ip in self.ip2waiting_list.keys()

    def refresh(self):
        # log_info(f"waiting list refresh!")
        # self.print_waiting_list()
        for key in self.ip2waiting_list.copy():
            log_info(
                f"Refresh: offset time = {(datetime.now() - self.ip2arp_request[key].last_request_time).total_seconds()}, ip = {key},  "
                f"request times = {self.ip2arp_request[key].request_times}")
            if (datetime.now() - self.ip2arp_request[key].last_request_time).total_seconds() >= self.interval_time:
                # send new arp packet
                if self.ip2arp_request[key].request_times < 5:
                    log_info(f"send arp request on {self.ip2arp_request[key].interface.name} to {key}")
                    self.router.router_send_packet(self.ip2arp_request[key].interface,
                                                   self.ip2arp_request[key].arp_request_packet)
                    self.ip2arp_request[key].last_request_time = datetime.now()
                    self.ip2arp_request[key].request_times += 1
                # delete item
                else:
                    log_info(f"delete ip = {key}")
                    del self.ip2arp_request[key]
                    del self.ip2waiting_list[key]

    def get_arp_reply(self, target_ip, target_mac, interface):
        # log_info(f"{len(self.waiting_list)}")
        log_info(f"get_arp_reply:target_ip={target_ip}, target_mac={target_mac}, interface={interface.name}")
        if self.is_ip_in_waiting_list(target_ip):
            log_info(f"arp reply for {target_ip} arrived!")
            if (datetime.now() - self.ip2arp_request[target_ip].last_request_time).total_seconds() > self.interval_time:
                log_info("arp reply packet out of waiting received time, do not receive")
                return
            ethernet_header = Ethernet(src=self.ip2arp_request[target_ip].interface.ethaddr, dst=target_mac)
            for packet in self.ip2waiting_list[target_ip]:
                final_packet = ethernet_header + packet.get_header(IPv4) + packet.get_header(ICMP)
                log_info("***********************************(send final packet)")
                log_info(f"final packet = {final_packet}")
                self.router.router_send_packet(interface, final_packet)
            # done this ip
            del self.ip2waiting_list[target_ip]
            del self.ip2arp_request[target_ip]


class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        self.arp_table = ArpTable(100)
        self.forward_table = IPForwardingTable(self)
        self.ipv4_packet_waiting_list = Ipv4PacketWaitingList(1, 5, self)
        self.send_packet_log = []
        # other initialization stuff here

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

        # handle arp reply packet
        arp_header = packet.get_header(Arp)
        if arp_header is not None and arp_header.operation == ArpOperation.Reply:
            log_info("!!#########################(receive arp reply packet) ")
            Router.handle_arp_reply_packet(self, arp_header)

        # handle arp request packet
        arp_header = packet.get_header(Arp)
        if arp_header is not None and arp_header.operation == ArpOperation.Request:
            log_info("??#########################(receive arp request packet)")
            Router.handle_arp_request_packet(self, arp_header, ifaceName, packet)

        # handle IPv4 packet
        ipv4_header = packet.get_header(IPv4)
        if ipv4_header is not None:
            log_info("receive IPv4 packet")
            log_info("###########################(receive ipv4 packet)")
            log_info(f"{packet}")
            Router.handle_ipv4_packet(self, ipv4_header, packet)

    def handle_arp_reply_packet(self, arp_header):
        sender_ip = arp_header.senderprotoaddr
        sender_mac = arp_header.senderhwaddr
        target_ip = arp_header.targetprotoaddr
        target_mac = arp_header.targethwaddr
        log_info(f"sender ip={sender_ip}, sender_mac={sender_mac}, target ip={target_ip}, target mac={target_mac}")
        if self.find_mac_by_ip(target_ip) is None:
            log_info("arp reply not for this router")
            return

        # add ip-mac into arp cache
        if not self.arp_table.is_ip_in_arp_table(sender_ip):
            log_info("add sender ip-mac to arp cache")
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
                log_info(f"target mac={target_mac}")
                for port in self.net.ports():
                    if port.name == interface_name:
                        ethernet_header = Ethernet(src=port.ethaddr, dst=target_mac)
                        self.router_send_packet(port, ethernet_header + ipv4_header + packet.get_header(ICMP))

    def handle_arp_request_packet(self, arp_header, ifaceName, packet):
        sender_ip = arp_header.senderprotoaddr
        sender_mac = arp_header.senderhwaddr
        target_ip = arp_header.targetprotoaddr
        target_mac = Router.find_mac_by_ip(self, target_ip)
        log_info(f"sender ip={sender_ip}, sender_mac={sender_mac}, target ip={target_ip}, target mac={target_mac}")
        if target_mac is None:
            log_info("arp request not for this router")
            return

        # add ip-mac into arp cache
        if not self.arp_table.is_ip_in_arp_table(sender_ip):
            self.arp_table.add_element(sender_ip, sender_mac)

        # if target_mac is not None and (not self.arp_table.is_ip_in_arp_table(target_ip)):
        #    self.arp_table.add_element(target_ip, target_mac)

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
                self.update()
            except NoPackets:
                continue
            except Shutdown:
                break
            self.update()
            self.handle_packet(recv)
            self.update()

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
