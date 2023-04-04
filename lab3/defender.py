from scapy.all import *
from scapy.layers.inet6 import IPv6, UDP, IP, TCP
import threading
import time

RES_INFO = 'Got msg:'
CUR_INFO = "Current data:"



class OutputThread(threading.Thread):
    NUMBER_OF_DOTS = 3

    def __init__(self, msg) -> None:
        super().__init__()

        self.__event = threading.Event()
        self.__msg = msg
        self.__cursor_pos = 0
        self.__sleep_time = 0.5
        self.__direction_up = True
        
    def __show_msg(self):
        print(self.__msg, '.' * abs(self.__cursor_pos - self.NUMBER_OF_DOTS), ' ' * (self.NUMBER_OF_DOTS - self.__cursor_pos), sep='', end='\r')
        # print(self.__msg, '.' * (self.NUMBER_OF_DOTS - self.__cursor_pos), ' ' * abs(self.__cursor_pos - self.NUMBER_OF_DOTS), sep='')
    
    def stop(self):
        print(self.__msg, '.' * self.NUMBER_OF_DOTS, sep='')
        self.__event.set()

    def run(self) -> None:

        while not self.__event.isSet():
            self.__show_msg()
            time.sleep(self.__sleep_time)
            # print(self.__cursor_pos)
            if self.__cursor_pos == self.NUMBER_OF_DOTS:
                self.__direction_up = False
                self.__cursor_pos -= 1
            
            elif self.__cursor_pos == 0:
                self.__direction_up = True
                self.__cursor_pos += 1
            
            elif not self.__direction_up:
                self.__cursor_pos -= 1
            
            else:
                self.__cursor_pos += 1
            

class Defender(threading.Thread):
    MY_PORT = 10005
    MAX_HLIM = 256
    DEFAULT_HLIM = 64

    def  __init__(self, recv_ip, recv_port, interface="lo"):
        super().__init__()

        self.daemon = True
        self.socket = None

        self.__stop_sniffer = threading.Event()
        self.__interface = interface
        self.__new_packet = True

        self.__recv_ip = recv_ip
        self.__recv_port = recv_port

        self.__got_hlims = []

    def run(self):
        self.socket = conf.L2listen(type=ETH_P_ALL, iface=self.__interface, filter=f"ip6 and dst port {self.MY_PORT}")
        sniff(opened_socket=self.socket, prn=self.__handle_packet, stop_filter=self.__should_stop_sniffer)

    def join(self, timeout=None):
        self.__stop_sniffer.set()
        super().join(timeout)

    def __should_stop_sniffer(self, packet):
        return self.__stop_sniffer.isSet()
    
    def __send_stop_packet(self):
        packet = IPv6(dst=self.__recv_ip)/UDP(dport=self.__recv_port)
        send(packet, verbose=False)
    
    def __send_to_recv(self):
        msg_thread = OutputThread('Sending normal packets')
        msg_thread.start()

        for hlim in self.__got_hlims:
            self.__send_normal_trafic(hlim) 

        msg_thread.stop()        
        msg_thread.join()

        self.__send_stop_packet()

        msg_thread = OutputThread('Sending packets with normalized fields')
        msg_thread.start()

        for hlim in self.__got_hlims:
            self.__normalize_fields() 

        msg_thread.stop()        
        msg_thread.join()
        
        self.__send_stop_packet()

        msg_thread = OutputThread('Sending extra trafic')
        msg_thread.start()
        
        for hlim in self.__got_hlims:
            self.__create_extra_trafic(hlim) 
        
        self.__send_stop_packet()

        msg_thread.stop()        
        msg_thread.join()

    def __send_normal_trafic(self, hlim):
        packet = IPv6(dst=self.__recv_ip, hlim=hlim)/TCP(dport=self.__recv_port)
        send(packet, verbose=False)
    
    def __normalize_fields(self):
        packet = IPv6(dst=self.__recv_ip, hlim=self.DEFAULT_HLIM)/TCP(dport=self.__recv_port)
        send(packet, verbose=False)

    def __create_extra_trafic(self, hlim):
        packet = IPv6(dst=self.__recv_ip, hlim=hlim)/TCP(dport=self.__recv_port)
        send(packet, verbose=False)
        packet = IPv6(dst=self.__recv_ip, hlim=hlim)/TCP(dport=self.__recv_port)
        send(packet, verbose=False)
    
    def __handle_packet(self, packet):
        if self.__new_packet:
            self.__new_packet = False
            return
        
        self.__new_packet = True
                
        if packet.getlayer(UDP):
            self.__send_to_recv()
            self.__got_hlims = []

            return
        
        tcp_layer = packet.getlayer(TCP)
        
        if tcp_layer and tcp_layer.ack != 0:
            return
                
        ip_layer = packet.getlayer(IPv6)
        hlim = ip_layer.hlim
        self.__got_hlims.append(hlim)

defender = Defender('localhost', 10010)
defender.start()

try:
    while True:
        time.sleep(2)

except KeyboardInterrupt:
    defender.join(0.1)

    if defender.is_alive():
        defender.socket.close()