import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy import all as scp
import argparse
import threading
from collections import deque
import time

MSS = 1400
RETRANSMIT_TIMEOUT = 2.0
DUMMY_PAYLOAD = '*' * MSS
H1_ADDR = '10.0.0.1'
H1_PORT = 20001
H2_ADDR = '10.0.0.2'
H2_PORT = 20002



class ClntTCP:
    def __init__(self, role, host, **kwargs):
        self.seq = 0
        self.next_seq = 1
        self.ack = 1
        self.pckt_get = deque()
        self.starred_seg = set()

        self.cwnd = 1 * MSS
        self.ssthresh = 64 * 1024
        self.dupack = 0
        self.state = "slow_start"
        self.seconds_retrans = None

        self.role = role
        self.log_cache = None

        if host == 'h1':
            self.src_ip = H1_ADDR
            self.dst_ip = H2_ADDR
            self.src_port = H1_PORT
            self.dst_port = H2_PORT

        if host == 'h2':
            self.src_ip = H2_ADDR
            self.dst_ip = H1_ADDR
            self.src_port = H2_PORT
            self.dst_port = H1_PORT

        self.limit = None
        if role == 'sender':
            if 'limit' in kwargs:
                self.limit = kwargs['limit']
        self.seq_log, self.ack_log = [], []
        self.log_attacker = False
        self.verbose = kwargs['verbose']

    def send(self):
        if self.limit and self.next_seq > self.limit:
            return
        packet = scp.IP(src=self.src_ip, dst=self.dst_ip) \
                 / scp.TCP(sport=self.src_port, dport=self.dst_port,
                           flags='', seq=self.next_seq) \
                 / (DUMMY_PAYLOAD)
        scp.send(packet, verbose=0)
        self.next_seq += MSS
        if self.seconds_retrans is None:
            self.seconds_retrans = time.time()
        self.xprint('\033[94m' + '(sent) data seq=%d:%d' % \
                    (packet[scp.TCP].seq, packet[scp.TCP].seq + MSS - 1) \
                    + '\033[0m')

    def resend(self, event):
        packet = scp.IP(src=self.src_ip, dst=self.dst_ip) \
                 / scp.TCP(sport=self.src_port, dport=self.dst_port,
                           flags='', seq=self.seq + 1) \
                 / (DUMMY_PAYLOAD)
        self.seconds_retrans = time.time()
        scp.send(packet, verbose=0)
        self.xprint('\033[93m' + '(resent:%s) data seq=%d:%d' % \
                    (event, packet[scp.TCP].seq, packet[scp.TCP].seq + MSS - 1) \
                    + '\033[0m')

    def send_ack(self, ack_no):
        packet = scp.IP(src=self.src_ip, dst=self.dst_ip) \
                 / scp.TCP(sport=self.src_port, dport=self.dst_port,
                           flags='A', ack=ack_no)
        scp.send(packet, verbose=0)
        self.ack_log.append((time.time() - self.base_time, ack_no))
        self.xprint('\033[94m' + '(sent) ack ack=%d' % ack_no + '\033[0m')

    def send_fin(self):
        packet = scp.IP(src=self.src_ip, dst=self.dst_ip) \
                 / scp.TCP(sport=self.src_port, dport=self.dst_port,
                           flags='F')
        scp.send(packet, verbose=0)
        if self.role == 'sender':
            msg = 'all data sent'
        else:
            msg = 'all data received'
        self.xprint('\033[94m' + '(sent) fin [%s]' % msg + '\033[0m')

    def timeout(self):
        if self.seconds_retrans is None:
            return
        elif self.seconds_retrans + RETRANSMIT_TIMEOUT < time.time():
            self.resend('timeout')
            self.state = "slow_start"
            self.ssthresh = self.cwnd / 2
            self.cwnd = 1 * MSS
            self.dupack = 0

    def post_receive(self, pkt, status):
        self.send_ack(self.ack)

    def receive(self):
        if len(self.pckt_get) == 0:
            return
        pkt = self.pckt_get.popleft()[0]

        if pkt[scp.TCP].flags == 0:
            self.seq_log.append((time.time() - self.base_time, pkt[scp.TCP].seq))
            self.xprint('\033[92m' + '(received) data seq=%d:%d' % \
                        (pkt[scp.TCP].seq, pkt[scp.TCP].seq + MSS - 1) \
                        + '\033[0m')
            if pkt[scp.TCP].seq == self.ack:
                status = 'new'
                self.ack += MSS
                while self.ack in self.starred_seg:
                    self.starred_seg.remove(self.ack)
                    self.ack += MSS
            elif pkt[scp.TCP].seq > self.ack:
                status = 'future'
                self.starred_seg.add(pkt[scp.TCP].seq)
            else:
                status = 'duplicate'
            self.post_receive(pkt, status)
        elif pkt[scp.TCP].flags & 0x10:
            self.xprint('\033[92m' + '(received) ack ack=:%d' % \
                        (pkt[scp.TCP].ack - 1) \
                        + '\033[0m')
            if pkt[scp.TCP].ack - 1 > self.seq:
                self.seq = pkt[scp.TCP].ack - 1

                self.seconds_retrans = time.time()
                if self.state == "slow_start":
                    self.cwnd += MSS
                elif self.state == "congestion_avoidance":
                    self.cwnd += MSS * MSS / self.cwnd
                elif self.state == "fast_recovery":
                    self.state = "congestion_avoidance"
                    self.cwnd = self.ssthresh
                self.dupack = 0
            else:

                self.dupack += 1
                if self.dupack < 3:
                    self.send()
                elif self.dupack == 3:
                    self.state = "fast_recovery"
                    self.ssthresh = self.cwnd / 2
                    self.cwnd = self.ssthresh + 3 * MSS

                    self.resend('triple-ack')
                elif self.state == "fast_recovery":
                    self.cwnd += MSS

        elif pkt[scp.TCP].flags & 0x1:  # FIN
            self.xprint('\033[92m' + '(received) fin' + '\033[0m')
            if self.role == 'sender' and self.state == 'fin_sent':
                return 'tear_down'
            if self.role == 'receiver':
                self.send_fin()
                return 'tear_down'

    def log_status(self):
        out = '(control:%s) cwnd=%d, ssthread=%d' % \
              (self.state, self.cwnd, self.ssthresh)
        if out != self.log_cache:
            self.xprint(out)
            self.log_cache = out

    def xprint(self, content):
        if not self.verbose: return
        timestamp = time.time() - self.base_time
        print
        '\033[1m' + '{:6.3f} '.format(timestamp) + '\033[0m' + content

    def begin_forwarder(self):
        self.xprint("retransmission timeout: %.1fs" % RETRANSMIT_TIMEOUT)
        last_log_time = 0
        while True:
            if self.state == "slow_start" and self.cwnd >= self.ssthresh:
                self.state = "congestion_avoidance"
            if self.next_seq - self.seq - 1 < self.cwnd:
                self.send()
            if self.receive() == 'tear_down':
                self.state = 'tear_down'
                break
            if self.state != 'fin_sent':
                self.timeout()

            if self.limit and self.seq >= self.limit:
                if self.state == 'fin_sent' \
                        and self.seconds_retrans + RETRANSMIT_TIMEOUT < time.time():
                    continue
                self.send_fin()
                self.seconds_retrans = 0
                self.state = 'fin_sent'

            self.log_status()

    def begin_accepter(self):
        while True:
            if self.receive() == 'tear_down':
                self.state = 'tear_down'
                break

    def listen(self):
        def paired_arry(pkt):
            return (pkt.haslayer(scp.IP) \
                    and pkt[scp.IP].src == self.dst_ip \
                    and pkt[scp.IP].dst == self.src_ip \
                    and pkt.haslayer(scp.TCP) \
                    and pkt[scp.TCP].sport == self.dst_port \
                    and pkt[scp.TCP].dport == self.src_port) \
                   and pkt[scp.TCP].flags & 0x4 == 0

        def line_arry(pkt):
            self.pckt_get.append((pkt, time.time()))

        def finish_arry(pkt):
            return pkt.haslayer(scp.TCP) \
                   and pkt[scp.TCP].flags & 0x1 != 0

        scp.sniff(lfilter=paired_arry,
                  prn=line_arry,
                  stop_filter=finish_arry)

    def write_logs_to_files(self):
        filename = 'cache_attack.txt' if self.log_attacker else 'cache.txt'
        f = open(filename, 'w')
        for time, seq in self.seq_log:
            f.write('%s,%.3f,%d\n' % ('seq', time, seq))
        for time, ack in self.ack_log:
            f.write('%s,%.3f,%d\n' % ('ack', time, ack))
        f.close()

    def start(self):
        listen_t = threading.Thread(target=self.listen)
        listen_t.daemon = True
        listen_t.start()

        self.base_time = time.time()
        self.xprint('connect begin')
        if self.role == 'sender':
            self.begin_forwarder()
        if self.role == 'receiver':
            self.begin_accepter()
        self.xprint('connect terminate')

        if self.role == 'receiver':
            self.xprint('write seq/ack arrays to folder')
            self.write_logs_to_files()
            self.xprint('write arrays finish')


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Naive TCP.")
    parser.add_argument('--role', dest='role',
                        required=True,
                        help="Part of TCP client ")
    parser.add_argument('--host', dest='host',
                        required=True,
                        help="Mininet host (`h1` or `h2`)")
    parser.add_argument('--rtt', dest='rtt', type=int,
                        help="Estimated RTT decisivid in Mininet .")
    parser.add_argument('--limit', dest='limit', type=int,
                        help="Restrict sum of data to forward .")
    parser.add_argument('--verbose', dest='verbose', action='store_true',
                        help="Flags for TCP communicate loging.")
    args = parser.parse_args()

    kwargs = {}
    if args.limit is not None:
        kwargs['limit'] = args.limit * 1000
    kwargs['verbose'] = args.verbose

    if args.rtt is not None:
        RETRANSMIT_TIMEOUT = max(1.0, args.rtt / 250.)

    tcp = ClntTCP(args.role, args.host, **kwargs)
    tcp.start()
