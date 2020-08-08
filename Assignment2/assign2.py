import socket
import sys


RUSH_PACKET_SIZE = 1500
PAYLOAD_SIZE = 1466
GET = '00100'
DAT = '00010'
FIN = '00001'
DAT_ACK = '10010'
DAT_NAK = '01010'
ACG_FIN = '10001'


def str_to_int(string, pad=PAYLOAD_SIZE):
    b_str = string.encode("UTF-8")
    if pad is not None:
        for i in range(len(string), pad):
            b_str += b'\0'
    return int.from_bytes(b_str, byteorder='big')


class Server:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('127.0.0.1', 0))
        self.file = ''
        self.client_seq = 0
        self.seq = 0
        self.packet = b''

    def run(self):
        print(self.socket.getsockname()[1])
        sys.stdout.flush()
        while True:
            if self.packet:     # has sent packet before
                try:
                    data, addr = self.socket.recvfrom(RUSH_PACKET_SIZE)
                except socket.timeout:
                    self.resend_packet(addr)
                    continue
            else:
                data, addr = self.socket.recvfrom(RUSH_PACKET_SIZE)

            seq_num = int.from_bytes(data[:2], byteorder='big')
            ack_num = int.from_bytes(data[2:4], byteorder='big')
            third_line = bin(int.from_bytes(data[4: 6], byteorder='big'))[2:].zfill(16)
            flags = third_line[:5]
            reserved = third_line[5:]
            if all([c == '0' for c in reserved]):
                if flags == GET:   # GET
                    if seq_num == 1 and ack_num == 0:
                        file_name = self.get_file_name(data[6:])
                        if file_name:  # file name exist
                            self.file = self.read_file(file_name)
                            self.send_packet(addr, seq_num)
                elif flags == DAT_ACK:    # DAT/ACK
                    if self.check_num(seq_num, ack_num) and not self.get_file_name(data[6:]):
                        if len(self.file) > 0:      # file sending is working
                            self.send_packet(addr, seq_num)
                        else:                       # file sending has finished (send FIN)
                            self.seq += 1
                            self.packet = self.make_packet(self.seq, 0, FIN)
                            self.socket.sendto(self.packet, addr)
                            self.client_seq = seq_num
                elif flags == DAT_NAK:    # DAT/NAK
                    if self.check_num(seq_num, ack_num) and not self.get_file_name(data[6:]):
                        if self.packet:
                            self.resend_packet(addr)
                            self.client_seq = seq_num
                elif flags == ACG_FIN:     # ACG/FIN
                    if self.check_num(seq_num, ack_num) and not self.get_file_name(data[6:]):
                        self.seq += 1
                        self.packet = self.make_packet(self.seq, seq_num, ACG_FIN)
                        self.socket.sendto(self.packet, addr)
                        self.socket.close()
                        sys.exit()

    def send_packet(self, addr, seq_num):
        self.socket.settimeout(None)
        self.seq += 1
        self.packet = self.make_packet(self.seq, 0, DAT, self.file[:PAYLOAD_SIZE])
        self.file = self.file[PAYLOAD_SIZE:]
        self.socket.sendto(self.packet, addr)
        self.client_seq = seq_num
        self.socket.settimeout(3)

    def resend_packet(self, addr):
        self.socket.sendto(self.packet, addr)
        self.socket.settimeout(3)
        
    def check_num(self, seq, ack):
        return seq == self.client_seq + 1 and ack == self.seq

    @staticmethod
    def make_packet(seq_num, ack_num, flags, file=None):
        header = ''
        header += bin(seq_num)[2:].zfill(16)
        header += bin(ack_num)[2:].zfill(16)
        header += flags.ljust(16, '0')
        if file is None:
            payload = (0).to_bytes(PAYLOAD_SIZE, byteorder='big')
        else:
            payload = str_to_int(file).to_bytes(PAYLOAD_SIZE, byteorder='big')
        return bytes([int(header[i:i + 8], 2) for i in range(0, 48, 8)]) + payload

    @staticmethod
    def get_file_name(payload):
        return payload.rstrip(b'\x00')

    @staticmethod
    def read_file(file_name):
        f = open(file_name, 'r')
        file = f.read()
        f.close()
        return file
    

if __name__ == '__main__':
    Server().run()
