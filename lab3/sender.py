import socket
import scapy

class Sender:
    def __init__(self, coder_ip, coder_port) -> None:
        self.__sock = socket.socket( socket.AF_INET6, socket.SOCK_STREAM )
        self.__sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.__sock.connect((coder_ip, coder_port))

    def send(self, data):
        self.__sock.send(data)

    def stop_sock(self):
        self.__sock.close()

class ConsoleUser:
    def __init__(self) -> None:
        self.__sender = Sender('localhost', 10000)

        self.start_input()

    def start_input(self):

        while True:
            try:
                data_to_send = input('Enter data to send: ')

                # if command == 'send':
                self.__sender.send(data_to_send.encode())

            except (KeyboardInterrupt, EOFError) as e:
                self.__sender.stop_sock()
                break;

if __name__ == '__main__':
    user = ConsoleUser()