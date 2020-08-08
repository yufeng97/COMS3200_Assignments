# -*- coding: UTF-8 -*-

import socket
from sys import argv
from urllib.parse import urlparse
from datetime import datetime, timedelta


class HTTPLogger:
    def __init__(self, url, server_port=80):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.url_info = self.exact_url_info(url)
        self.url = self.url_info[0] + "://" + self.url_info[1] + self.url_info[2]
        self.server_port = server_port

    def make_connection(self):
        self.sock.connect((self.url_info[1], self.server_port))
        self.sock.sendall(self.make_request(self.url_info[1], self.url_info[2]))

    def reconnect(self, new_url):
        self.sock.close()
        self.url_info = self.exact_url_info(new_url)
        if self.url_info[0] != "https":
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.make_connection()
            self.print_ip_port()
            data = self.get_response_data()
            status_code = data[0][9:12]
            return self.detect_status_code(status_code, data)
        else:
            print("HTTPS Not Supported")

    def get_response_data(self):
        buffer = []
        while True:
            d = self.sock.recv(1024)  # receive 1kb at most
            if d:
                buffer.append(d)
            else:
                break
        response = b''.join(buffer).decode('utf-8')
        return response.split('\r\n')

    def print_ip_port(self):
        print("Client:", self.sock.getsockname()[0], self.sock.getsockname()[1])
        print("Server:", self.sock.getpeername()[0], self.sock.getpeername()[1])

    def detect_status_code(self, status_code, data):
        if status_code[0] == '2':
            print("Retrieval Successful")
            self.print_date(data)
            self.write_file(self.get_content_type(data), data[len(data) - 1])
            return
        elif 400 <= int(status_code) <= 599:
            print("Retrieval Failed ({})".format(status_code))
            return
        elif status_code == '301':
            redirect_url = self.get_redirection(data)
            print("Resource permanently moved to", redirect_url)
            self.reconnect(redirect_url)
        elif status_code == '302':
            redirect_url = self.get_redirection(data)
            print("Resource temporarily moved to", redirect_url)
            self.reconnect(redirect_url)

    def run(self):
        print("URL Requested:", self.url)
        if self.url_info[0] != "https":
            self.make_connection()
            data = self.get_response_data()
            self.print_ip_port()
            status_code = data[0][9: 12]
            self.detect_status_code(status_code, data)
            self.sock.close()
        else:
            print("HTTPS Not Supported")

    @staticmethod
    def exact_url_info(url):
        protocol = ''
        host = ''
        path = ''
        parse_tuple = urlparse(url)
        if parse_tuple.scheme == "http" or parse_tuple.scheme == "https":  # url start with http:// or https://
            protocol += parse_tuple.scheme
            host += parse_tuple.netloc
            if parse_tuple.path == '':  # no / in the end
                path += '/'
            else:
                path += parse_tuple.path
        elif parse_tuple.scheme == '':  # url start without protocol
            protocol += "http"
            if parse_tuple.path.find('/') != -1:  # url exist /
                host += parse_tuple.path.split('/', 1)[0]
                path += '/' + parse_tuple.path.split('/', 1)[1]
            else:
                host += parse_tuple.path
                path += '/'
        return protocol, host, path

    @staticmethod
    def make_request(host, path):
        request = "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n"
        return request.encode("utf-8")

    @staticmethod
    def print_date(data):
        is_find = False
        for line in data:
            if len(line) != 0:
                if line[0:4] == "Date":
                    converted_date = datetime.strptime(line[6:], "%a, %d %b %Y %H:%M:%S %Z") + timedelta(hours=10)
                    print("Date Accessed:", converted_date.strftime("%d/%m/%Y %H:%M:%S AEST"))
                elif line[0:13] == "Last-Modified":
                    converted_date = datetime.strptime(line[15:], "%a, %d %b %Y %H:%M:%S %Z") + timedelta(hours=10)
                    print("Last Modified:", converted_date.strftime("%d/%m/%Y %H:%M:%S AEST"))
                    is_find = True
                    break
        if not is_find:
            print("Last Modified not available")

    @staticmethod
    def get_redirection(data):
        for line in data:
            words = line.split()
            if len(words) != 0 and words[0][0:8] == "Location":
                return words[1]

    @staticmethod
    def get_content_type(data):
        for line in data:
            words = line.split()
            if len(words) != 0 and words[0][0:12] == "Content-Type":
                return words[1]

    @staticmethod
    def write_file(content_type, text):
        extension = ''
        if content_type == "text/plain":
            extension += ".txt"
        elif content_type == "text/html":
            extension += ".html"
        elif content_type == "text/css":
            extension += ".css"
        elif content_type == "text/javascript" or content_type == "application/javascript":
            extension += ".js"
        elif content_type == "application/json":
            extension += ".json"
        with open("output" + extension, 'w', encoding="utf-8") as file:
            file.write(text)


if __name__ == '__main__':
    url = argv[1]
    logger = HTTPLogger(url)
    logger.run()
