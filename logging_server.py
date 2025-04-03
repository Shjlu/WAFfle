import socket, struct

LOGGING_PORT = 7070

CODE_INDEX = 0
WRITE_LOG = '1'
READ_LOG = '2'
LENGTH_ALLOWED_FOR_LOG = 301


def write_log(msg):
    with open("logging.log", "a") as log_file:
        log_file.write(msg + '\n')


def read_log():
    with open("logging.log", "r") as log_file:
        logs = log_file.read()
    return logs


def start_logging():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_address = (('localhost', LOGGING_PORT))
    server_socket.bind(server_address)
    server_socket.listen()
    while True:
        client, address = server_socket.accept()

        msg = client.recv(LENGTH_ALLOWED_FOR_LOG).decode()

        if msg[CODE_INDEX] == WRITE_LOG:
            write_log(msg[1:])
        elif msg[CODE_INDEX] == READ_LOG:

            logs = read_log()

            msg = struct.pack(">I", len(logs))
            msg += logs.encode()

            client.sendall(msg)
        client.close()
