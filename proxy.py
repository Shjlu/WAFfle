import socket
from datetime import date

from modules.http_request import HttpRequest, HTTPSmuggling, SQLInjection, DirectoryTraversal, XXEAttack
from modules.sqli_checker import SQLiChecker
from modules.db import DB, WebsiteAddress
from modules.directoryTraversal import DirectoryTraversalChecker
from modules.db import DB
from modules.XXEChecker import XXEChecker
import modules.logging as logging
import ssl
from modules.DosChecker import detect_DOS_attack
import requests
from multiprocessing import Queue
import threading
import code
import queue
import time
from enum import Enum


class MsgType(Enum):
    READ = 0
    WRITE = 1
    DELETE = 2


class UrgencyLevel(Enum):
    DEFAULT = 0
    DAILY = 1
    WEEKLY = 2
    MONTHLY = 3
    QUARTERLY = 4
    YEARLY = 5
    NEVER = 255


class LogType(Enum):
    PROXY_UP = 1
    PROXY_DOWN = 2
    USER_REQUEST = 4
    ATTACK_ATTEMPT = 8
    BLOCKED_USER_ENTRY = 16


def get_country_code(ip: str) -> str:
    result = requests.get(f'http://ip-api.com/json/{ip}?fields=countryCode')
    print(result.json())
    try:
        return result.json()['countryCode']
    except:
        return 'no contry >:('


class Proxy(object):
    def __init__(self, db, config):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ssock = None  # for HTTPS connections
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((config.proxy_ip, config.proxy_port))
        self.config = config

        self.sql_checker = SQLiChecker(db)
        self.xxe_checker = XXEChecker(db)
        self.directory_traversal_checker = DirectoryTraversalChecker(db)

        self.db: DB = db

    def listen(self):
        """Opens the listening socket, and handles each client
        """

        # Create a queue for communication between threads
        proxy_message_queue = queue.Queue()
        detector_message_queue = queue.Queue()

        # Create and start the interpreter thread
        interpreter_thread = threading.Thread(target=detect_DOS_attack,
                                              args=(proxy_message_queue, detector_message_queue))
        interpreter_thread.start()

        self.sock.listen()
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile='server.crt', keyfile='server.key')  # certification
        self.ssock = context.wrap_socket(self.sock, server_side=True)

        while True:
            try:
                client, address = self.ssock.accept()

                proxy_message_queue.put(address)

                if address[0] in self.db.get_all_blocked_ip():
                    client.close()
                    self.db.add_to_logs(log_type=int(LogType.BLOCKED_USER_ENTRY.value), ip=address[0], message="Blocked User tried to enter")
                    continue

                if not detector_message_queue.empty():
                    message = detector_message_queue.get()
                    self.db.add_to_blacklist(message[0], time.ctime(time.time()), "tried DOS attack")
                    self.db.add_to_logs(log_type=int(LogType.ATTACK_ATTEMPT.value), ip=address[0], message="attempting Dos attack")

                client.settimeout(60)
                threading.Thread(target=self.listenToClient, args=(client, address)).start()

            except Exception as e:
                print(e)
                

    def forward_request(self, request):
        """Forwards request to website

        :param request: The HTTP request
        :type request: bytes
        :return: response from server
        :rtype: bytes
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        address: WebsiteAddress = self.db.get_address_by_domain(request.headers['Host'].split(':')[0])

        sock.connect((address.ip, address.port))
        sock.settimeout(3)
        print(request.to_bytes())
        sock.send(request.to_bytes())

        response = b""
        while b"\r\n\r\n" not in response:
            data = sock.recv(4096)
            if not data:
                break
            response += data
        headers, body = response.split(b"\r\n\r\n", 1)
        resp_obj = HttpRequest.headers_obj(response)
        remaining_len = 0
        if "Content-Length" in resp_obj.headers:
            remaining_len = int(resp_obj.headers["Content-Length"]) - len(body)

        while remaining_len:
            data = sock.recv(remaining_len)
            response += data
            remaining_len -= len(data)

        sock.close()
        return response

    def listenToClient(self, client, address):
        """The client handler, receives the request and runs the necessary tests

        :param client: client socket
        :type client: socket.socket
        :param address: client address
        :type address: str
        """

        print('listening to client')
        while True:
            try:
                req, data = HttpRequest.from_socket(client)

                if "Host" not in req.headers:
                    client.send(b"HTTP/1.1 400 Bad Request\r\n"
                                b"Content-Type: text/plain\r\n"
                                b"Content-Length: 39\r\n"
                                b"Connection: close\r\n"
                                b"\r\n"
                                b"400 Bad Request: Host header is missing")
                    client.close()  # couldn't route
                    return
                if get_country_code(req.headers['Host']) in self.db.get_blocked_countries(
                        req.headers['Host'].split(':')[0]):
                    client.close()
                    return  # just kill the connection

                
                #  Checking for attacks attempts
                self.sql_checker.isMalicious(req)
                self.xxe_checker.isMalicious(req)
                self.directory_traversal_checker.isMalicious(req)
                    

                serv_resp = self.forward_request(req)
                client.send(serv_resp)
                client.close()
                return

            except SQLInjection as e:
                self.db.add_to_blacklist(address[0], time.ctime(time.time()), "tried SQL injection attack")
                self.db.add_to_logs(log_type=int(LogType.ATTACK_ATTEMPT.value), ip=address[0], message="attempting SQL Injection")
                client.close()  # malicious request
                return

            except DirectoryTraversal as e:
                self.db.add_to_blacklist(address[0], time.ctime(time.time()), "tried Directory traversal attack")
                self.db.add_to_logs(log_type=int(LogType.ATTACK_ATTEMPT.value), ip=address[0], message="attempting Directory traversal attack")
                client.close()  # malicious request
                return

            except HTTPSmuggling as e:
                self.db.add_to_blacklist(address[0], time.ctime(time.time()), "tried HTTP smuggling attack")
                self.db.add_to_logs(log_type=int(LogType.ATTACK_ATTEMPT.value), ip=address[0], message="attempting HTTP smuggling attack")
                client.close()  # malicious request
                return

            except XXEAttack as e:
                self.db.add_to_blacklist(address[0], time.ctime(time.time()), "tried XXE attack")
                self.db.add_to_logs(log_type=int(LogType.ATTACK_ATTEMPT.value), ip=address[0], message="attempting XXE attack")
                client.close()  # malicious request
                return

            except Exception as e:
                print(e)
                print(type(e).__name__)
                client.close()
                return
