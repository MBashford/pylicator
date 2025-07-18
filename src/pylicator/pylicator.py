#!/usr/bin/env python 
"""A tool for forwarding recieved SNMP traps to multiple adresses.
Might work for other traffic too, inspired by samplicator"""
__author__ = "Milo Bashford"

import argparse
import configparser
import datetime
import ipaddress
import os.path
import signal
import socket
import string
import struct
import sys
import threading

import asn1

from typing import Union


class pylicator():

    def __init__(self, conf_path="pylicator.conf"):

        self.__forwd_rules = {}
        self.__forwd_rules_str = []

        self.__log_path = "pylicator.log"
        self.__data_log_path = "pylicator-data.log"
        self.__log_lock = threading.Lock()
        self.__data_log_lock = threading.Lock()

        self.__count_out = 0
        self.__count_out_lock = threading.Lock()
        
        self.__set_conf_path(conf_path)
        self.__parse_config()

        self.__srv_sock = self.__init_socket(self.__listen_addr, self.__listen_port)

        signal.signal(signal.SIGTERM, self.__exit)
        signal.signal(signal.SIGINT, self.__exit)


    def __set_conf_path(self, conf_path):

        default_path = "pylicator.conf"

        # use default if nothing passed
        if conf_path is None:
            parsed_path = default_path
        # if file exists or path ends in .conf - assume file,
        elif os.path.isfile(conf_path) or conf_path[-5:] == ".conf":
            parsed_path = conf_path
        # othwerwise treat as dir path and use default conf name
        else:
            parsed_path = os.path.join(conf_path, default_path)
            
        self.__conf_file = parsed_path


    def __set_log_path(self, path):

        default_path = self.__log_path
        
        if path in [None, ""]:
            self.__log_path = default_path
        elif os.path.isfile(path):
            self.__log_path = path
        elif os.path.isdir(path):
            self.__log_path = os.path.join(path, default_path)
        elif os.path.isdir(os.path.dirname(path)):
            self.__log_path = path
        elif os.path.basename(path) == path:
            self.__log_path = path
        else:
            self.__log_path = default_path


    def __set_data_log_path(self, path):

        default_path = self.__data_log_path

        if path in [None, ""]:
            self.__data_log_path = default_path
        elif os.path.isfile(path):
            self.__data_log_path = path
        elif os.path.isdir(path):
            self.__data_log_path = os.path.join(path, default_path)
        elif os.path.isdir(os.path.dirname(path)):
            self.__data_log_path = path
        elif os.path.basename(path) == path:
            self.__data_log_path = path
        else:
            self.__data_log_path = default_path
            

    def __parse_config(self):

        try:
            if os.path.exists(self.__conf_file) == False:
                self.__write_logs("----------------------\n" +
                                "Initialising Pylicator\n" +
                                "----------------------\n" +
                                "No config file found. Generating config with default values at:\n" +
                                f"{os.path.abspath(self.__conf_file)}")
                self.__gen_config()

            conf_file = configparser.ConfigParser()
            conf_file.read(self.__conf_file)

            log_traps = conf_file.get("settings", "log_traps")
            log_bytes = conf_file.get("settings", "log_bytes")
            log_path = conf_file.get("settings", "log_path")
            data_log_path = conf_file.get("settings", "data_log_path")
            listen_port = conf_file.get("settings", "listen_port")
            spoof_src = conf_file.get("settings", "spoof_src")

            self.__set_log_path(log_path)
            self.__set_data_log_path(data_log_path)

            self.__write_logs("----------------------\n" +
                            "Initialising Pylicator\n" +
                            "----------------------\n" +
                            f"Parsing config from {os.path.abspath(self.__conf_file)}")

            if log_path not in [None, ""] and log_path not in self.__log_path:            
                self.__write_logs(f"WARNING: Can't access {log_path}, logs will be generated in:\n" +
                                f"{os.path.abspath(self.__log_path)}")
            
            if data_log_path not in [None, ""] and data_log_path not in self.__data_log_path:  
                self.__write_logs(f"WARNING: Can't access {data_log_path}, data logs will be generated in:\n" +
                                f"{os.path.abspath(self.__data_log_path)}") 

            if self.__log_path == self.__data_log_path:
                self.__write_logs(f"Writing logs and data to same file")
                self.__data_log_lock = self.__data_log_lock     # use same lock to avoid overwriting 

            self.__log_traps = True if log_traps.lower() == "true" else False
            self.__log_bytes = True if log_bytes.lower() == "true" else False
            self.__listen_addr = "0.0.0.0"
            self.__listen_port = int(listen_port)
            self.__spoof_src = True if spoof_src.lower() == "true" else False

            for l in conf_file.items("forwarding_rules"):
                self.__set_forwarding_rule(l[0], l[1])

        except Exception as e:
            self.__write_logs(["FATALERROR: Unable to parse config file", str(e)])
            self.__exit(status=1)
            

    def __gen_config(self):
        conf_file = configparser.ConfigParser(allow_no_value=True)

        conf_file.add_section("settings")
        conf_file.set("settings", "# if log_bytes = True traps wil be also be logged as bytearrays for debugging")
        conf_file.set("settings", "# if spoof_src = True maintains original source ips in forwarded traps")
        conf_file.set("settings", "listen_port", "162")
        conf_file.set("settings", "log_traps", "False")
        conf_file.set("settings", "log_bytes", "False")
        conf_file.set("settings", "log_path", "")
        conf_file.set("settings", "data_log_path", "")
        conf_file.set("settings", "spoof_src", "False")

        conf_file.add_section("forwarding_rules")
        conf_file.set("forwarding_rules", "# <origin> = <destination-1> <destination-2>")
        conf_file.set("forwarding_rules", "0.0.0.0/0", "172.0.0.1:162 192.168.1.86:162")
        conf_file.set("forwarding_rules", "172.0.0.1/32", "172.0.0.1:5432 192.168.0.1:4321")

        # ensure dirpath to denerated conf file
        dir_path = os.path.dirname(self.__conf_file)
        if dir_path != "":
            os.makedirs(dir_path, exist_ok=True)

        with open(self.__conf_file, "w") as fp:
            conf_file.write(fp)

        self.__write_logs(["Config file sucessfully created"])
        self.__exit(status=0)


    def __set_forwarding_rule(self, orig: str, dest:str):
        try:
            if orig in self.__forwd_rules:
                raise Exception(f"Duplicate forwarding rules for origin {orig}")
            
            orig_net = ipaddress.IPv4Network(orig)
            self.__forwd_rules[orig] = {
                "netw": int(orig_net.network_address),
                "mask": int(orig_net.netmask),
                "frwd_addr": self.__parse_forwading_address_str(dest)
            }
            self.__forwd_rules_str.append(f"{orig} > {dest}") # store as text for printing

        except Exception as e:
            self.__write_logs([f"FATALERROR: Unable to set forwading rule for Origin '{orig}'", str(e)])
            self.__exit(status=1)


    def __parse_forwading_address_str(self, addr_str: str) -> list:
        """Parse string of <address>:<port> combinations from config"""
        addrs = addr_str.split(" ")
        parsed = []
        for addr in addrs:
            addr_port = addr.split(":")

            # check destination ips are valid
            if len(addr_port) == 1:
                self.__write_logs(f"WARNING: No port specified for destination {addr_port[0]}.\nUsing port 162 as default")
                addr_port.append("162")

            if len(addr_port) != 2:
                raise Exception(f"Expected destination address in format '<ip_address>:<port>', instead got {addr_port}")
            
            if (int(addr_port[1]) > 65535) or (int(addr_port[1]) < 1):
                raise Exception(f"{addr_port[1]} is not a valid port")

            try:
                ipaddress.IPv4Address(addr_port[0])
            except:
                raise Exception(f"FATALERROR: {addr_port[0]} is not a valid IP address")
            
            parsed.append((addr_port[0], int(addr_port[1])))
                
        return parsed


    def __init_socket(self, address, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind((address, port))
        except Exception as e:
            self.__write_logs([f"FATALERROR: Could not bind socket to port {port}", str(e)])
            self.__exit(status=1)
        return sock


    def __write_to_file(self, f_path: str, lock: threading.Lock, msg: Union[str, list]):
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S:%f")
        pad = "                          "
        if type(msg) == str:
            msg = msg.splitlines()
        lines = [str(l).lstrip() for l in msg]
        lock.acquire()
        with open(f_path, "a") as file:
            start = True
            for l in lines:
                file.write(f"{ts if start else pad} :: {l} \n")
                start = False
        lock.release()


    def __write_data_logs(self, data):
        try:
            dest = ", ".join([f"{d[0]}:{d[1]}" for d in data[1]]) # join all forwarding addr
            entry = [f"{data[0][0]}:{data[0][1]} > {dest} {self.__decode_asn1(data[2])}"]
            if self.__log_bytes:
                entry.append(data[2])
            self.__write_to_file(self.__data_log_path, self.__data_log_lock, entry)
        except Exception as e:
            self.__write_logs(["ERROR: Unable to write data logs", str(e)])


    def __write_logs(self, entry):
        try:
            self.__write_to_file(self.__log_path, self.__log_lock, entry)
        except Exception as e:
            print("ERROR: Logging failed - This may or may not be critical", file=sys.stderr)
            print(e, file=sys.stderr)
            print(entry, file=sys.stderr)


    def __handle_io(self, data: bytes, orig: tuple):
        try:
            dest = self.__get_forwarding_addresses(orig[0])
            if len(dest) < 1:
                # if address is not in any defined subnet
                self.__write_logs(f"WARNING: trap received from {orig[0]} originates outside allowed subnets")

            if self.__log_traps:
                self.__write_data_logs((orig, dest, data))

            for d in dest:               
                self.__send(orig, d, data)

        except Exception as e:
            self.__write_logs([f"ERROR: failed on handleIO from {orig}", str(e)])


    def __get_forwarding_addresses(self, orig: str) -> set:
        dest = set()
        orig = int(ipaddress.IPv4Address(orig))
        for rule in self.__forwd_rules:
            r = self.__forwd_rules[rule]
            if (orig & r["mask"] == r["netw"]):
                dest.update(r["frwd_addr"])
        return dest


    def __send(self, origin: tuple, dest: tuple, data: bytes):
        try:
            c = self.__iter_count_out()
            if self.__spoof_src:
                # build custom ip packet
                pack = Packet(origin, dest, data, c)
                with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as sock:
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, True)
                    sock.sendto(pack.get_ip_packet(), dest)
            else:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.connect(dest)
                    sock.send(data)
        except Exception as e:
            self.__write_logs([f"ERROR: couldn't forward to {dest[0]}:{dest[1]}", str(e)])


    def __decode_asn1(self, byte_str):
        """Naive decoder, returns string with PDU contents as OID=Value pairs"""

        def naive_parse(tag, val: bytes):
            "try to resolve bytes not understood by asn1 decoder"
            try:
                # Unknowns (0)
                if tag.nr == 0:
                    # try to parse as IPV4 address
                    if len(val) == 4:
                        val = ".".join([str(oct) for oct in val])

                # parse bool (1), and
                # parse integer (2), and
                # parse bitstring as int (3)
                elif tag.nr in [1, 2, 3]:
                    val = str(val).replace("\\x", "")[2:-1]
                    for char in val:
                        if char not in set(string.hexdigits):
                            val = val.replace(char, char.encode().hex())
                    val = int(val, 16)

                # parse octet string (4)
                elif tag.nr == 4:
                    val = f"\"{val.decode()}\""

            except:
                val = f"\"{str(val)[2:-1]}\""

            return val
        
        try:

            def decode_mill(input: asn1.Decoder):
                out_str = ""
                flag = False
                    
                while not input.eof():
                    tag = input.peek()
                    # work around: asn1 module update appears to have broken eof()
                    if tag is None:
                        break
                    if tag.typ == asn1.Types.Primitive:
                        tag, val = input.read()
                        if type(val) is bytes:
                            val = naive_parse(tag, val)
                        out_str += f"{'=' if flag else '  '}{val}"
                        if tag.nr == 6 and flag == False:
                            flag = True
                        else:
                            flag = False

                    elif tag.typ == asn1.Types.Constructed:
                        input.enter()
                        out_str += decode_mill(input)
                        input.leave()
                return out_str

            dec = asn1.Decoder()
            dec.start(byte_str)

            # get snmp version
            # 0 = SNMPv1, 1 = SNMPv2c, 3 = SNMPv3

            dec.enter()
            tag, ver = dec.read()

            # only try to read v1 and v2c traps
            if  ver< 3:
                val = decode_mill(dec)
                val_split = val.split("  ", 3)
                val = f"C={val_split[1]} SNMPv{'1' if ver==0 else '2c'}  {val_split[-1]}"

            else:
                val = f"SNMPv{ver} - Unable to decrypt contents"

            return val
        

        except  Exception as e:
            self.__write_logs([f"WARNING: Error parsing ASN1", e])
            val = byte_str

        return val
    

    def __iter_count_out(self) -> int:
        self.__count_out_lock.acquire()
        c = self.__count_out
        self.__count_out = 0 if self.__count_out == 65535 else self.__count_out + 1
        self.__count_out_lock.release()
        return c
    

    def __exit(self, status=0, *args):
        try:
            
            if self.__log_lock.locked():
                self.__log_lock.release()
            if self.__data_log_lock.locked():
                self.__data_log_lock.release()

            self.__write_logs("---------------------\n" +
                            "Terminating Pylicator\n" +
                            "---------------------")
            
        except Exception as e:
            print(e)

        finally:
            sys.exit(status)
     

    def pylicate(self):

        self.__write_logs(f"Running pylicate on port: {self.__listen_port}\n" + 
                          ("---Logging snmp trap contents---\n" if self.__log_traps else "") +
                          ("---Spoofing source IP Address---\n" if self.__spoof_src else "") +
                          "Forwarding Rules\n" +
                          "----------------\n" +
                          "\n".join(self.__forwd_rules_str))

        while True:
            try:
                in_sock = self.__srv_sock
                data, addr = in_sock.recvfrom(4096)
            
            except Exception as e:
                self.__write_logs(["FATALERROR: Listen failed on socket", str(e)])
                self.__exit(status=1)

            threading.Thread(target=self.__handle_io, args=(data, addr)).start()


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


if __name__ == "__main__":

    # get passed args
    psr = argparse.ArgumentParser()
    psr.add_argument("-c", "--conf-path", type=str)
    args = psr.parse_args()

    py = pylicator(conf_path=args.conf_path)
    py.pylicate()