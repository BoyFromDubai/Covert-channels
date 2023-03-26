import threading
import socket
from scapy.layers.inet6 import IPv6, TCP, UDP
from scapy.all import *
import random

class Receiver:
    MAX_HOP_LIMIT = 256

    def __init__(self, ip, port) -> None:
        self.__ip = ip
        self.__port = port

        # self.__sock = socket.socket( socket.AF_INET6, socket.SOCK_STREAM )
        # self.__sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # self.__sock.connect((self.__ip, self.__port))

    def __code_pkt(self, bit):
        sec_rand_lim = None

        if bit == 0:
            sec_rand_lim = random.randrange(0, self.MAX_HOP_LIMIT // 2)
        else:
            sec_rand_lim = random.randrange(self.MAX_HOP_LIMIT // 2, self.MAX_HOP_LIMIT)

        packet = IPv6(dst=self.__ip, hlim=sec_rand_lim)/TCP(dport=self.__port)
        
        return packet

    def __create_stop_packet(self): return IPv6(dst=self.__ip)/UDP(dport=self.__port)

    def __send_pkt(self, pkt):
        send(pkt, verbose=False)


    def send_secret_msg(self, data):
        data_to_send = list(map(lambda x: format(x, '08b'), bytearray(data)))

        for byte in data_to_send:
            for bit in byte:
                self.__send_pkt(self.__code_pkt(int(bit)))

        self.__send_pkt(self.__create_stop_packet())

class SenderConn(threading.Thread):
    BUF_SIZE = 10
    TIMEOUT = 1.0

    def __init__(self, sock) -> None:
        super().__init__()
        self.__sock = sock
        self.__sock.settimeout(self.TIMEOUT)

        self.__stop_flag = threading.Event()

        self.__receiver = Receiver('localhost', 6010)


    def stop(self): self.__stop_flag.set()

    def __close_sock(self): self.__sock.close()

    def _get_data(self):
        buff = self.__sock.recv(self.BUF_SIZE)
        message_ended = False
        
        while not message_ended:
            self.__sock.settimeout(self.TIMEOUT)
            
            try:
                chunk = self.__sock.recv(self.BUF_SIZE)
                
                if not chunk:
                    message_ended = True
                else:
                    buff += chunk

            except socket.timeout:
                message_ended = True

        return buff

    def __handle_data(self, data):
        self.__receiver.send_secret_msg(data)

    def run(self):
        while not self.__stop_flag.is_set():
            try:
                got_data = self._get_data()
                
                if got_data == b'':
                    self.stop()
                    continue
                
                self.__handle_data(got_data)
                
            except socket.timeout:
                continue

            except socket.error as e:
                raise e
            
        self.__close_sock()

class Serv(threading.Thread):
    TIMEOUT = 1.0

    def __init__(self, ip, port) -> None:
        super().__init__()
        self.__ip = ip
        self.__port = port
        self.__sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        self.__sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.__sock.bind((self.__ip, self.__port))
        self.__sock.settimeout(self.TIMEOUT)
        self.__sock.listen(1)

        self.__stop_flag = threading.Event()

        self.__sender = None

    def __close_sock(self): 
        if self.__sender:
            self.__sender.stop()
        
        self.__sock.close()

    def stop(self): self.__stop_flag.set()

    def run(self):
        while not self.__stop_flag.is_set():
            try:
                sock, addr = self.__sock.accept()
                print(f'{addr[0]}:{addr[1]} connected')
                self.__sender = SenderConn(sock)
                self.__sender.start()
                self.__sender.join()

            except socket.timeout:
                continue

        self.__close_sock()
        
    def __repr__(self) -> str:
        return f'Listening on {self.__ip}:{self.__port}'        

if __name__ == '__main__':
    serv = Serv('localhost', 6005)
    
    try:    
        serv.start()
        
        print(serv)
        
        serv.join()

    except (KeyboardInterrupt, EOFError):
        serv.stop()
