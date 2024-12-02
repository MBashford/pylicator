#!/usr/bin/env python 
"""A tool for forwarding recieved SNMP traps to multiple adresses.
Might work for other traffic too, inspired by samplicator"""
__author__ = "Milo Bashford"

import socket
import datetime
import threading
import configparser
import os.path


test_out = [
    {
        "address": "localhost",
        "port": 162
    }
]

class pylicator():

    def __init__(self):

        # init with defaults
        self.debug = False
        self.__listen_addr = ""
        self.__listen_port = 23
        self.__forwd_addr = [
            {
                "address": "localhost",
                "port": 162
            }
        ]

        self.__log_file = "pylicator.log"
        self.__data_log_file = "pylicator-data.log"
        self.__log_lock = threading.Lock()
        self.__data_log_lock = threading.Lock()

        self.__parse_config()

        self.__srv_sock = self.__init_socket(self.__listen_addr, self.__listen_port)


    def __parse_config(self):
        file_name = r"pylicator.conf"

        if os.path.exists(file_name) == False:
            self.__write_logs("No config file found. Generating config with default values")
            self.__gen_config(file_name)

        conf_file = configparser.ConfigParser()
        conf_file.read(file_name)

        debug = conf_file.get("default_settings", "debug")
        listen_addr = conf_file.get("default_settings", "listen_addr")
        listen_port = conf_file.get("default_settings", "listen_port")

        self.debug = True if debug.lower() == "true" else False
        self.__listen_addr = "" if  listen_addr.lower() == "none" else listen_addr
        self.__listen_port = int(listen_port)

        forwd_addr = []
        for l in conf_file.items("forwarding_settings"):
            port_address = l[1].split(":")
            forwd_addr.append({
                "address":port_address[0],
                "port": int(port_address[1])
            })

        self.__forwd_addr = forwd_addr
            

    def __gen_config(self, file_name):
        conf_file = configparser.ConfigParser(allow_no_value=True)

        conf_file.add_section("default_settings")
        conf_file.set("default_settings", "# debug = True will log contents of redirected datagrams")
        conf_file.set("default_settings", "# listen_addr = none is equivalent to 0.0.0.0/32")
        conf_file.set("default_settings", "#                only accepts ipv4 addresses")
        conf_file.set("default_settings", "#                subnets not yet supported")
        conf_file.set("default_settings", "debug", "False")
        conf_file.set("default_settings", "listen_addr", "localhost")
        conf_file.set("default_settings", "listen_port", "23")

        conf_file.add_section("forwarding_settings")
        conf_file.set("forwarding_settings", "# list as [ip address][port no]")
        conf_file.set("forwarding_settings", "addr1", "localhost:162")

        with open(file_name, "w") as fp:
            conf_file.write(fp)

        self.__write_logs("Config file sucessfully created")


    def __init_socket(self, address, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind((address, port))
        except Exception as e:
            self.__write_logs(f"FATALERROR: Could not bind socket to port {port}")
            self.__write_logs(e)
            exit(1)
        return sock


    def __write_data_logs(self, data):
        try:
            ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S:%f")
            self.__data_log_lock.acquire()
            with open(self.__data_log_file, "a") as file:
                file.write(f"{ts} :: {data[0]} :: {data[1]} \n")
            self.__data_log_lock.release()
        except Exception as e:
            self.__write_logs("ERROR: Unable to write data logs")
            self.__write_logs(e)


    def __write_logs(self, entry):
        try:
            ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S:%f")
            self.__log_lock.acquire()
            with open(self.__log_file, "a") as file:
                file.write(f"{ts} :: {entry} \n")
            self.__log_lock.release()
        except Exception as e:
            print("ERROR: Logging failed - This may or may not be critical")
            print(e)


    def __handle_io(self, data, addr):
        try:   
            if self.debug:
                self.__write_data_logs((addr, data))

            for f in self.__forwd_addr:               
                self.__send(f["address"], f["port"], data)

        except Exception as e:
            self.__write_logs(f"ERROR: failed to on handleIO from {addr}")
            self.__write_logs(e)


    def __send(self, addr, port, data):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect((addr, port))
                sock.send(data)
        except Exception as e:
            self.__write_logs(f"ERROR: couldn't forward to {addr}/{port}")
            self.__write_logs(e)


    def pylicate(self):

        self.__write_logs(f"""Running pylicate (Debug = {self.debug})
            Listening on {self.__listen_addr}/{self.__listen_port}""")

        while True:
            try:
                in_sock = self.__srv_sock
                data, addr = in_sock.recvfrom(4096)
            
            except Exception as e:
                self.__write_logs("FATALERROR: Listen failed on socket")
                self.__write_logs(e)
                exit(1)

            threading.Thread(target=self.__handle_io, args=(data, addr)).start()


if __name__ == "__main__":
    py = pylicator()
    py.pylicate()