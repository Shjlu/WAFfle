import socket
import time
import logging_server

LOGGING_SERVER_PORT = 7070
WRITE_LOG_CODE = "1"


def write_log(blocked_user="", msg=""):
    # Create a TCP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    server_address = ('localhost', LOGGING_SERVER_PORT)
    client_socket.connect(server_address)

    if blocked_user != "":
        log = WRITE_LOG_CODE + time.ctime(time.time()) + " " + blocked_user + " was blocked due to, " + msg
        client_socket.sendall(log.encode())
    else:
        log = WRITE_LOG_CODE + time.ctime(time.time()) + " " + msg
