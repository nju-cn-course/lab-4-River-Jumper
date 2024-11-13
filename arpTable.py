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
        ip = str(ip)
        if not self.is_ip_in_arp_table(ip):
            log_info(f"Arp tabel: add {ip} - {mac}")
            self.dict[ip] = [mac, datetime.now()]

        elif self.dict[ip][0] != mac:
            # TODO: delete this line
            '''
            if str(ip) == '10.10.128.20' and str(mac) == '34:00:00:00:01:20':
                return
            '''
            log_info(f"update {ip}'s mac from {self.dict[ip][0]} to {mac}")
            self.dict[ip][0] = mac
        self.print_arc_table()

    def is_ip_in_arp_table(self, ip):
        ip = str(ip)
        if ip in self.dict.keys():
            self.dict[ip][1] = datetime.now()
            return self.dict[ip][0]
        return False

    def update_element(self, ip, mac):
        ip = str(ip)
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
