import socket
import sys
import ipaddress
import threading

HEADER_LENGTH = 20


class Application:
    def __init__(self, ip_addr, port):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("localhost", port))
        self.ip_addr = ipaddress.ip_interface(ip_addr)
        self.gateway = None
        self.arp = {}
        self.mtu = 1500
        self.length = 0
        self.offset = 0
        self.flags = '000'
        self.identifier = 0
        self.received = {}

    def set_gateway(self, ip_addr):
        ip = self.string_to_ip(ip_addr)
        self.gateway = ip

    def get_gateway(self):
        print(self.gateway)

    def set_arp(self, ip_addr, port):
        ip = self.string_to_ip(ip_addr)
        if ip:
            self.arp[ip] = int(port)
        else:
            print('Invalid ip address format')

    def get_arp(self, ip_addr):
        ip = self.string_to_ip(ip_addr)
        if ip:
            print(self.arp.get(ip))
        else:
            print('Invalid ip address format')

    def set_mtu(self, value):
        self.mtu = int(value)

    def get_mtu(self):
        print(self.mtu)

    def exit(self):
        self.socket.close()
        sys.exit()

    def listen(self):
        while True:
            data, addr = self.socket.recvfrom(2048)
            self.unpack_packet(data)

    def unpack_packet(self, data):
        header = data[:20]
        message = data[20:].decode('utf-8')
        src_ip = ipaddress.ip_address(header[12: 16])
        dst_ip = ipaddress.ip_address(header[16: 20])
        length = int.from_bytes(header[2: 4], 'big')
        id = int.from_bytes(header[4: 6], 'big')
        flags_offset = header[6: 8]
        flags_offset_string = bin(int.from_bytes(flags_offset, byteorder='big'))[2:].zfill(16)
        flags = flags_offset_string[:3]
        offset = int(flags_offset_string[3:], 2)
        protocol = header[9]  # notice this is an integer
        # print(data, "flags:", flags, "protocol:", protocol)
        tup = (offset, length, protocol, flags, message)

        if self.received.get(src_ip) is None:
            self.received[src_ip] = {}
            self.received[src_ip][id] = []
            self.received[src_ip][id].append(tup)
        else:
            if self.received[src_ip].get(id) is None:
                self.received[src_ip][id] = []
            self.received[src_ip][id].append(tup)
        self.concatenate_message()

    def concatenate_message(self):
        # dictionary structure: {src_ip -> {id -> packet_list}}
        for src_ip, value in self.received.items():
            for index in list(value):
                find_last = False
                packets = value[index]
                total_length = 0
                for i in range(len(packets)):
                    if packets[i][3] == '000':
                        find_last = True
                        break
                if find_last:
                    total_length = packets[i][0] * 8 + packets[i][1]
                calculated_total_length = 0
                for packet in packets:
                    calculated_total_length += packet[1] - HEADER_LENGTH
                calculated_total_length += HEADER_LENGTH
                if find_last and total_length == calculated_total_length:
                    packets = sorted(packets, key=lambda tup: tup[0])
                    message = ''
                    for packet in packets:
                        message += packet[4]
                    protocol = packets[0][2]
                    if protocol == 0:
                        print('\b\bMessage received from {}: "{}"\n> '.format(src_ip, message), end='')
                    else:
                        print('\b\bMessage received from {} with protocol {}\n> '.format(src_ip, '0x{:02x}'.format(protocol)), end='')
                    sys.stdout.flush()
                    value.pop(index)

    def send_message(self, ip_addr, message):
        if message[0] != '"' and message[-1] != '"':
            print('Invalid message')
            return
        message_to_send = message[1:][:-1]
        ip = self.string_to_ip(ip_addr)
        src_ip = str(self.ip_addr.ip)
        if self.is_subnet(ip):                  # send by ARP
            if self.arp.get(ip) is not None:
                port = self.arp.get(ip)
                self.send_packet(src_ip, ip, message_to_send, port)
            else:
                print('No ARP entry found')
        else:                                   # send to gateway
            if self.arp.get(self.gateway) is not None:
                port = self.arp.get(self.gateway)
                self.send_packet(src_ip, ip, message_to_send, port)
            else:
                print('No gateway found')

    def send_packet(self, src_ip, dst_ip, message, port):
        message_to_send = message
        addr = ('localhost', port)
        self.length = 0
        self.offset = 0
        self.flags = '000'
        while message_to_send:
            if len(message_to_send) > self.mtu - HEADER_LENGTH:
                self.length = self.mtu
                self.flags = '001'
            else:
                self.length = len(message_to_send) + HEADER_LENGTH
                self.flags = '000'
            packet = self.make_packet(self.ip_to_binary(src_ip), self.ip_to_binary(dst_ip), self.length,
                                      self.identifier, self.offset, self.flags,
                                      message_to_send[:self.mtu - HEADER_LENGTH])
            self.socket.sendto(packet, addr)
            self.offset += (self.mtu - HEADER_LENGTH) // 8
            message_to_send = message_to_send[self.mtu - HEADER_LENGTH:]
        if self.offset == 0 and message == '':
            packet = self.make_packet(self.ip_to_binary(src_ip), self.ip_to_binary(dst_ip), HEADER_LENGTH,
                                      self.identifier, self.offset, self.flags, message)
            self.socket.sendto(packet, addr)
        self.identifier += 1

    def is_subnet(self, ip):
        if ip.find('.') == -1:
            return ipaddress.ip_address(int(ip)) in self.ip_addr.network
        else:
            return ipaddress.ip_address(ip) in self.ip_addr.network

    @staticmethod
    def make_packet(src_ip, dst_ip, length, identifier, offset, flags, payload):
        header_dict = {
            'version_IHL': '01000101',
            'tos': ''.zfill(8),
            'total_length': bin(length)[2:].zfill(16),
            'identification': bin(identifier)[2:].zfill(16),
            'flags': flags,
            'offset': bin(offset)[2:].zfill(13),
            'TTL': bin(64)[2:].zfill(8),
            'protocol': ''.zfill(8),
            'checksum': ''.zfill(16),
            'src_ip': src_ip,
            'destination_ip': dst_ip,
        }
        header = ''.join(str(x) for x in header_dict.values())
        return bytes([int(header[i: i + 8], 2) for i in range(0, 160, 8)]) + payload.encode('utf-8')

    @staticmethod
    def ip_to_binary(ip):
        return ''.join([bin(int(x))[2:].zfill(8) for x in ip.split('.')])

    @staticmethod
    def string_to_ip(s):
        try:
            if s.find('.') == -1:
                ip = str(ipaddress.ip_address(int(s)))
            else:
                ip = str(ipaddress.ip_address(s))
            return ip
        except ValueError:
            return None

    def run(self):
        t = threading.Thread(target=self.listen, name='ListeningThread')
        t.setDaemon(True)
        t.start()
        func = {
            1: {'exit': self.exit},
            2: {'gw': self.get_gateway, 'mtu': self.get_mtu},
            3: {'gw': self.set_gateway, 'arp': self.get_arp, 'msg': self.send_message, 'mtu': self.set_mtu},
            4: {'arp': self.set_arp}
        }
        while True:
            user_input = input('> ')
            command = user_input.split()
            if len(command) == 4:
                func[4][command[0]](command[2], command[3])
            elif len(command) == 3:
                if command[0] == 'msg':
                    func[3][command[0]](command[1], command[2])
                else:
                    func[3][command[0]](command[2])
            elif len(command) == 2:
                func[2][command[0]]()
            elif len(command) == 1:
                func[1][command[0]]()


def main(argv):
    if len(argv) < 3:
        print("Usage: python3 assign3.py ip-addr ll-addr")
        return
    ip_addr = argv[1].split('/')
    if len(ip_addr) == 2:
        if int(ip_addr[1]) > 32:
            print("Invalid ip-addr")
            return
    else:
        print("Invalid ip-addr")
        return
    app = Application(argv[1], int(argv[2]))
    app.run()


if __name__ == '__main__':
    main(sys.argv)
