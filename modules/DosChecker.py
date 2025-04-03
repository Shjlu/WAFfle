from multiprocessing import Queue

import threading
import code
import queue
import time

CONNECTIONS_LIMIT = 4

# const values

IP_INDEX = 0
CONNECTIONS_AMOUNT = 0
LAST_RESET_TIME = 1

TIME_SEGMENT_FOR_RESET = 60


def detect_DOS_attack(proxy_q, detector_q):
    local_vars = {}
    users_entrances = {}

    interpreter = code.InteractiveConsole(local_vars, filename='<stdin>')
    while True:
        try:

            new_connection_user = proxy_q.get()  # Wait for data from the main thread

            if new_connection_user[
                0] in users_entrances.keys():  # checks for the current IP in the connection dictionary
                users_entrances[new_connection_user[IP_INDEX]][CONNECTIONS_AMOUNT] += 1
            else:
                users_entrances[new_connection_user[IP_INDEX]] = [1,
                                                                  time.time()]  # (amount of connections, last update timer)

            if users_entrances[new_connection_user[IP_INDEX]][CONNECTIONS_AMOUNT] > CONNECTIONS_LIMIT:
                detector_q.put(new_connection_user)

            if time.time() - users_entrances[new_connection_user[IP_INDEX]][LAST_RESET_TIME] >= TIME_SEGMENT_FOR_RESET:
                users_entrances[new_connection_user[IP_INDEX]][LAST_RESET_TIME] = time.time()
                users_entrances[new_connection_user[IP_INDEX]][CONNECTIONS_AMOUNT] = 0


        except:
            pass
