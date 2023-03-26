from scapy.all import sniff, AsyncSniffer
from scapy.layers.inet6 import IPv6, TCP, UDP
import socket
import time

MY_PORT = 6010 

class Decoder:
    MAX_HLIM = 256

    def __init__(self) -> None:
        self.__new = True
        self.__bytes_arr = [[]]

        self.__cur_byte = 0
        self.__cur_bit = 0

    def update_bytes_arr(self, packet):

        if packet.haslayer(UDP):
            return
        
        if not self.__new:
            self.__new = True
            return
        
        bit = packet[IPv6].hlim
        print(bit)
        
        if self.__cur_bit == 8:
            self.__cur_bit = 0
            self.__cur_byte += 1
            self.__bytes_arr.append([])
        
        self.__bytes_arr[self.__cur_byte].insert(self.__cur_bit, bit)
        
        self.__cur_bit += 1
        self.__new = False

    def __decode_bytes(self):
        res_bytes = []
        
        for i in range(len(self.__bytes_arr)):
            res_bytes.append('')

            for j in range(len(self.__bytes_arr[i])):
                if self.__bytes_arr[i][j] < self.MAX_HLIM // 2:
                    res_bytes[i] += str(0)
                else:
                    res_bytes[i] += str(1)

        return res_bytes

    def decode_msg(self):
        if not self.__bytes_arr[0]:
            raise ValueError('Nothing to decode!')

        res = ''
        res_bytes = self.__decode_bytes()

        for byte in res_bytes:
            res += chr(int(byte, 2))

        return res

    def __repr__(self):
        return str(self.__bytes_arr)

while True:
    
    decoder = Decoder()
    sniffer = sniff(iface='lo', filter=f"port {MY_PORT}", prn=decoder.update_bytes_arr, stop_filter = lambda x: x.haslayer(UDP))
    
    try:
        res = decoder.decode_msg()
        print(res)
    
    except ValueError:
        break
