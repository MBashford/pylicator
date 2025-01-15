#!/usr/bin/env python 
"""Class and methods for building ip packets"""
__author__ = "Milo Bashford"

import struct
from typing import Union

class Packet():

    def __init__(self, origin: tuple, dest: tuple, payload: Union[str, bytes], count: int=4219):

        self.__origin_ip = struct.pack("!4B", *[int(i) for i in origin[0].split(".")])
        self.__origin_port = origin[1]
        self.__dest_ip = struct.pack("!4B", *[int(i) for i in dest[0].split(".")])
        self.__dest_port = dest[1]

        self.__count = count
        self.__payload = payload if type(payload) is bytes else payload.encode()

        self.__udp_dgram = self.__build_udp_datagram()
        self.__ip_packet = self.__build_ip_packet()


    def __build_ip_packet(self) -> bytes:
        
        ip_hl = 69  # corresponds to IPV4 header byte 01000101
        tos = 0
        total_len = 20 + len(self.__udp_dgram)
        id = self.__count
        flags_offset = 0    # governs datagram fragmentation
        ttl = 128
        protocol = 17       # udp

        ip_header = struct.pack("!BBHHHBBH", ip_hl, tos, total_len, id, flags_offset, ttl, protocol, 0) + self.__origin_ip + self.__dest_ip
        return ip_header + self.__udp_dgram


    def __build_udp_datagram(self) -> bytes:

        total_len = 8 + len(self.__payload)
        pseudo_header = self.__origin_ip + self.__dest_ip + struct.pack("!BBH", 0, 17, total_len)
        udp_header = struct.pack("!4H", self.__origin_port, self.__dest_port, total_len, 0)
        checksum = self.__calc_checksum(pseudo_header + udp_header + self.__payload)
        return udp_header[:6] + struct.pack("!H", checksum) + self.__payload


    def __calc_checksum(self, data: bytes) -> int:
        checksum = 0
        data_len = len(data)
        if (data_len % 2):
            data_len += 1
            data += struct.pack("!B", 0)
        
        for i in range(0, data_len, 2):
            w = (data[i] << 8) + (data[i + 1])
            checksum += w

        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum = ~checksum & 0xFFFF
        return checksum


    def get_ip_packet(self):
        return self.__ip_packet
    
    def get_udp_datagram(self):
        return self.__udp_dgram
    
