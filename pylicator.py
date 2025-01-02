#!/usr/bin/env python 
"""A tool for forwarding recieved SNMP traps to multiple adresses.
Might work for other traffic too, inspired by samplicator"""
__author__ = "Milo Bashford"

import socket
import datetime
import threading
import configparser
import os.path
import sys
import ipaddress

import asn1


class pylicator():

    def __init__(self):

        self.__forwd_rules = {}
        self.__forwd_rules_str = []

        self.__log_path = ""
        self.__log_file = "pylicator.log"
        self.__data_log_file = "pylicator-data.log"
        self.__log_lock = threading.Lock()
        self.__data_log_lock = threading.Lock()

        self.__parse_config()

        self.__srv_sock = self.__init_socket(self.__listen_addr, self.__listen_port)


    def __parse_config(self):
        file_name = r"pylicator.conf"

        try:
            if os.path.exists(file_name) == False:
                self.__write_logs("No config file found. Generating config with default values")
                self.__gen_config(file_name)

            conf_file = configparser.ConfigParser()
            conf_file.read(file_name)

            log_traps = conf_file.get("settings", "log_traps")
            log_bytes = conf_file.get("settings", "log_bytes")
            log_path = conf_file.get("settings", "log_path")
            listen_port = conf_file.get("settings", "listen_port")

            if log_path != "" and os.path.exists(log_path):
                self.__log_path = log_path
            elif log_path != "":
                self.__write_logs(f"WARNING: Can't access directory {log_path}, logs will be generated in the local dir") 

            self.__log_traps = True if log_traps.lower() == "true" else False
            self.__log_bytes = True if log_bytes.lower() == "true" else False
            self.__listen_addr = "0.0.0.0"
            self.__listen_port = int(listen_port)

            for l in conf_file.items("forwarding_rules"):
                self.__set_forwarding_rule(l[0], l[1])

        except Exception as e:
            self.__write_logs(["FATALERROR: Unable to parse config file", str(e)])
            exit(1)
            

    def __gen_config(self, file_name):
        conf_file = configparser.ConfigParser(allow_no_value=True)

        conf_file.add_section("settings")
        conf_file.set("settings", "# if log_bytes = True traps wil be also be logged as bytearrays for debugging")
        conf_file.set("settings", "listen_port", "162")
        conf_file.set("settings", "log_traps", "False")
        conf_file.set("settings", "log_bytes", "False")
        conf_file.set("settings", "log_path", "")

        conf_file.add_section("forwarding_rules")
        conf_file.set("forwarding_rules", "# <origin> = <destination-1> <destination-2>")
        conf_file.set("forwarding_rules", "0.0.0.0/0", "172.0.0.1:162 192.168.1.86:162")
        conf_file.set("forwarding_rules", "172.0.0.1/32", "172.0.0.1:5432 192.168.0.1:4321")

        with open(file_name, "w") as fp:
            conf_file.write(fp)

        self.__write_logs("Config file sucessfully created")


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
            self.__write_logs([f"FATALERROR: Unable to set forwading rule", str(e)])
            exit(1)


    def __parse_forwading_address_str(self, addr_str: str) -> list:
        """Parse string of <address>:<port> combinations from config"""
        addrs = addr_str.split(" ")
        parsed = []

        try:
            for addr in addrs:
                addr_port = addr.split(":")

                # check passed ips are valid
                if len(addr_port) != 2:

                    raise Exception(f"Expected address in format '<ip_address>:<port>', instead got {addr_port}")
                if (int(addr_port[1]) > 65535) or (int(addr_port[1]) < 1):
                    raise Exception(f"{addr_port[1]} is not a valid port")
                
                ipaddress.IPv4Address(addr_port[0])
                parsed.append((addr_port[0], int(addr_port[1])))
                

        except Exception as e:
            self.__write_logs([f"FATALERROR: Unable to parse forward address", e])
            exit(1)

        return parsed


    def __init_socket(self, address, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind((address, port))
        except Exception as e:
            self.__write_logs([f"FATALERROR: Could not bind socket to port {port}", str(e)])
            exit(1)
        return sock


    def __write_to_file(self, f_name: str, lock: threading.Lock, msg: str | list):
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S:%f")
        f_path = os.path.join(self.__log_path, f_name)
        pad = "                          "
        if type(msg) == str:
            msg = msg.splitlines()
        lines = [l.lstrip() for l in msg]
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
            self.__write_to_file(self.__data_log_file, self.__data_log_lock, entry)
        except Exception as e:
            self.__write_logs(["ERROR: Unable to write data logs", str(e)])


    def __write_logs(self, entry):
        try:
            self.__write_to_file(self.__log_file, self.__log_lock, entry)
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
                self.__send(d[0], d[1], data)

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


    def __send(self, addr, port, data):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect((addr, port))
                sock.send(data)
        except Exception as e:
            self.__write_logs([f"ERROR: couldn't forward to {addr}:{port}", str(e)])


    def __decode_asn1(self, byte_str):
        """Naive decoder, returns string with PUD contents as OID=Value pairs"""
        try:
            dec = asn1.Decoder()
            dec.start(byte_str)

            def decode_mill(input: asn1.Decoder):
                out_str = ""
                is_data = False
                
                while not input.eof():
                    tag = input.peek()
                    if tag.typ == asn1.Types.Primitive:
                        tag, val = input.read()
                        val = val.decode(errors="backslashreplace") if type(val) is bytes else val
                        out_str += f"{'=' if is_data else ' '}{val}"
                        is_data = not is_data

                    elif tag.typ == asn1.Types.Constructed:
                        input.enter()
                        out_str += decode_mill(input)
                        input.leave()
                return out_str

            val = decode_mill(dec)

            # first value pair: SNMPVersion=CommunityString
            # second two appear to be null vals
            # errors in decoding seem to be the ans1 decoder unable to understand ip tags

            val_split = val.split(" ", 3)
            desc = f"C=\"{val_split[1][2:]}\" SNPMV{int(val_split[1][0])+1}"
            val = f"{desc} {val_split[-1]}"
            

        except  Exception as e:
            self.__write_logs(["ERROR: Failed to decode received msg", str(e)])
            val = byte_str

        return val


    def pylicate(self):

        self.__write_logs(f"Running pylicate on port: {self.__listen_port}\n" + 
                          ("---Logging snmp trap contents---\n" if self.__log_traps else "") +
                          "Forwarding Rules\n" +
                          "----------------\n" +
                          "\n".join(self.__forwd_rules_str))

        while True:
            try:
                in_sock = self.__srv_sock
                data, addr = in_sock.recvfrom(4096)
            
            except Exception as e:
                self.__write_logs(["FATALERROR: Listen failed on socket", str(e)])
                exit(1)

            threading.Thread(target=self.__handle_io, args=(data, addr)).start()


if __name__ == "__main__":
    py = pylicator()
    py.pylicate()