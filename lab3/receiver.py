from scapy.all import *
from scapy.layers.inet6 import IPv6, UDP, IP, TCP
import threading
from time import sleep

RES_INFO = 'Got msg:'
CUR_INFO = "Current data:"

class Decoder(threading.Thread):
    MY_PORT = 10010
    MAX_HLIM = 256

    def  __init__(self, interface="lo"):
        super().__init__()

        self.daemon = True
        self.socket = None

        self.__interface = interface
        self.__stop_sniffer = threading.Event()
        self.__new_packet = True
        self.__cur_byte = 0
        self.__cur_bit = 0
        self.__msg = ''

    def run(self):
        self.socket = conf.L2listen(type=ETH_P_ALL, iface=self.__interface, filter=f"ip6 and dst port {self.MY_PORT}")
        sniff(opened_socket=self.socket, prn=self.__handle_packet, stop_filter=self.__should_stop_sniffer)

    def join(self, timeout=None):
        self.__stop_sniffer.set()
        super().join(timeout)

    def __should_stop_sniffer(self, packet):
        return self.__stop_sniffer.isSet()
    
    def __handle_packet(self, packet):
        if self.__new_packet:
            self.__new_packet = False
            return
        
        self.__new_packet = True

        if packet.getlayer(UDP):
            print(RES_INFO, self.__msg, ' ' * (len(CUR_INFO) - len(RES_INFO) if len(CUR_INFO) > len(RES_INFO) else 0))
            self.__cur_bit = 0
            self.__cur_byte = 0
            self.__msg = ''
            
            return

        tcp_layer = packet.getlayer(TCP)
        
        if tcp_layer and tcp_layer.ack != 0:
            return
        
        ip_layer = packet.getlayer(IPv6)
        hlim = ip_layer.hlim
        bit = 0 if hlim < self.MAX_HLIM // 2 else 1
        self.__msg += str(bit)
        self.__cur_bit += 1

        if self.__cur_bit == 8:
            self.__cur_bit = 0
            self.__msg = self.__msg[:self.__cur_byte] + chr(int(self.__msg[self.__cur_byte:self.__cur_byte + 8], 2))
            self.__cur_byte += 1

        print(CUR_INFO, self.__msg, " " * 8, end='\r')

decoder = Decoder()
decoder.start()

try:
    while True:
        sleep(2)

except KeyboardInterrupt:
    decoder.join(0.1)

    if decoder.is_alive():
        decoder.socket.close()