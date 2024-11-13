import ipaddress
import pdb
import time
from datetime import datetime

import switchyard
from switchyard.lib.userlib import *
from typing import Dict


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

        # self.print_forwarding_table()

    def print_forwarding_table(self):
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
