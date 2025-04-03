from scapy.all import *
from collections import Counter
from time import localtime, strftime
import threading

SYN = 2
ACK = 0x10
SYN_FLOOD_CAP = 50

attack_flag = False
blackList = set()
syn_count = Counter()


class ClearCacheThread(threading.Thread):
    def run(self):
        """This function clears the syn counter and blacklists the people who attempt to DOS
        """

        global attack_flag, blackList

        while True:
            if attack_flag:
                i = 0
                most_common = syn_count.most_common()
                for (address, count) in most_common:
                    if count <= SYN_FLOOD_CAP:
                        break

                    print(f"Blacklisted IP {address} due to being a naughty boi and sending {count} requests")
                    blackList.add(address)
                    attack_flag = False

            syn_count.clear()
            time.sleep(1)


def packet_handler(pkt):
    """Packet handler. counts syns from each client. Turn attack flag on if one of the clients sends too much syns

    :param pkt: the scapy packet to check
    :type pkt: scapy packet
    """
    global attack_flag, syn_count

    if TCP in pkt and \
            (src := pkt.sprintf('{IP:%IP.src%}{IPv6:%IPv6.src%}')) not in blackList and \
            (pkt[TCP].flags & SYN) and \
            not pkt[TCP].flags & ACK:

        syn_count[src] += 1
        if syn_count[src] > SYN_FLOOD_CAP:
            attack_flag = True


class DosDetector(threading.Thread):
    def run(self):
        ClearCacheThread().start()
        sniff(prn=packet_handler, store=0)


if __name__ == "__main__":
    DosDetector().start()
