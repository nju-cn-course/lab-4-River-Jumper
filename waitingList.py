import ipaddress
import pdb
import time
from threading import Timer

import switchyard
from switchyard.lib.userlib import *
from typing import Dict


class Ipv4PacketWaitingList:
    class ArpRequestMessage:
        def __init__(self, arp_request_packet, interface, last_request_time, request_times):
            self.arp_request_packet = arp_request_packet
            self.interface = interface
            self.last_request_time = last_request_time
            self.request_times = request_times
            self.last_refresh_time = time.time()

    def __init__(self, interval_time, max_request_times, router):
        self.interval_time = interval_time
        self.max_request_times = max_request_times
        self.waiting_list = []
        self.router = router
        self.ip2waiting_list = {}
        self.ip2arp_request = {}
        self.total_refresh_time = 0

    def print_waiting_list(self):
        log_info("----------------------------------------------------(waiting list)")
        for key in self.ip2waiting_list.keys():
            log_info(f"ip:{key}, num:{len(self.ip2waiting_list[key])}, times: {self.ip2arp_request[key].request_times}")
        log_info("----------------------------------------------------")

    # target ip must in waiting list, request times must < 5
    def __waiting_list_send_arp_request(self, target_ip):
        self.router.router_send_packet(self.ip2arp_request[target_ip].interface,
                                       self.ip2arp_request[target_ip].arp_request_packet)
        self.ip2arp_request[target_ip].request_times += 1

        log_info("**************************(send arp request)")
        log_info(
            f"send arp request packet from {self.ip2arp_request[target_ip].interface.name} to {target_ip}, "
            f"already send arp request {self.ip2arp_request[target_ip].request_times} times, "
            f"time offset = {time.time() - self.ip2arp_request[target_ip].last_request_time}, "
            f"request times = {self.ip2arp_request[target_ip].request_times}")
        self.ip2arp_request[target_ip].last_request_time = time.time()

    def send_arp_request_loop(self, next_hop_ip):
        # end loop situation 1
        if next_hop_ip not in self.ip2waiting_list.keys():
            return
        # end loop situation 2
        if self.ip2arp_request[next_hop_ip].request_times >= 5:
            self.del_packet(next_hop_ip)
        # send packet and prepare next loop
        else:
            # send arp request to next_hop_ip
            self.__waiting_list_send_arp_request(next_hop_ip)
            # next loop
            Timer(self.interval_time, Ipv4PacketWaitingList.send_arp_request_loop, args=(self, next_hop_ip)).start()

    def add_packet(self, packet, interface, next_hop_ip):
        log_info(f"Waiting list: add dst({next_hop_ip}) on {interface}")
        if next_hop_ip not in self.ip2waiting_list.keys():
            self.ip2waiting_list[next_hop_ip] = []
            self.ip2waiting_list[next_hop_ip].append(packet)
            # make arp request packet
            arp_request_packet = create_ip_arp_request(interface.ethaddr, interface.ipaddr, next_hop_ip)
            self.ip2arp_request[next_hop_ip] = self.ArpRequestMessage(arp_request_packet, interface,
                                                                      time.time(), 0)

            # solution1: send arp request loop
            # self.send_arp_request_loop(next_hop_ip)
            # solution2: first send arp request then start refresh before each loop

            if self.ip2arp_request[next_hop_ip].request_times < 5:
                self.__waiting_list_send_arp_request(next_hop_ip)

            self.refresh()

        else:
            self.ip2waiting_list[next_hop_ip].append(packet)
        self.print_waiting_list()

    def del_packet(self, next_hop_ip):
        log_info(f"delete ip = {next_hop_ip}")
        del self.ip2arp_request[next_hop_ip]
        del self.ip2waiting_list[next_hop_ip]
        self.print_waiting_list()

    def is_ip_in_waiting_list(self, ip):
        return ip in self.ip2waiting_list.keys()

    def refresh(self):
        self.total_refresh_time += 1
        log_info(f"Refresh! total refresh time = {self.total_refresh_time}")
        # log_info(f"waiting list refresh!")
        # self.print_waiting_list()
        for key in self.ip2waiting_list.copy():
            if time.time() - self.ip2arp_request[key].last_refresh_time >= 0.2:
                log_info(
                    f"Refresh: offset time = {time.time() - self.ip2arp_request[key].last_request_time}, ip = {key},  "
                    f"request times = {self.ip2arp_request[key].request_times}")
                self.ip2arp_request[key].last_refresh_time = time.time()
            if time.time() - self.ip2arp_request[key].last_request_time >= self.interval_time:
                # send new arp packet
                if self.ip2arp_request[key].request_times < 5:
                    log_info("**************************(send arp request)")
                    log_info(
                        f"send arp request on {self.ip2arp_request[key].interface.name} to {key}, offset time = {time.time() - self.ip2arp_request[key].last_request_time}")
                    self.router.router_send_packet(self.ip2arp_request[key].interface,
                                                   self.ip2arp_request[key].arp_request_packet)
                    self.ip2arp_request[key].last_request_time = time.time()
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
            log_info(f"offset time = {time.time() - self.ip2arp_request[target_ip].last_request_time}")
            log_info(f"arp reply for {target_ip} arrived!")
            if time.time() - self.ip2arp_request[target_ip].last_request_time > self.interval_time:
                log_info("arp reply packet out of waiting received time, do not receive")
                return
            ethernet_header = Ethernet(src=self.ip2arp_request[target_ip].interface.ethaddr, dst=target_mac)
            for packet in self.ip2waiting_list[target_ip]:
                '''
                if packet.get_header(ICMP) is not None:
                    final_packet = ethernet_header + packet.get_header(IPv4) + packet.get_header(ICMP)
                elif packet.get_header(UDP) is not None:
                    final_packet = (ethernet_header + packet.get_header(IPv4) +
                                    packet.get_header(UDP) + packet.get_header(RawPacketContents))
                else:
                    final_packet = ethernet_header + packet.get_header(IPv4)
                '''

                log_info(f"packet = {packet}")
                log_info(f"ethernet_header = {ethernet_header}")
                packet.prepend_header(ethernet_header)

                log_info("***********************************(send Ipv4 packet)")
                log_info(f"new packet = {packet}")

                self.router.router_send_packet(interface, packet)
            # done this ip
            del self.ip2waiting_list[target_ip]
            del self.ip2arp_request[target_ip]
