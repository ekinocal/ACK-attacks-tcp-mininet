from mininet.topo import Topo
import argparse
from mininet.net import Mininet
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.util import dumpNodeConnections
import time
import os
import matplotlib.pyplot as schm
import argparse
from ack import check_attack_sort

GRPH_FLDR = "graphs"


def get_rows(f, d):
    lines = f.readlines()[:-1]
    for line in lines:
        sort, time, num = line.split(',')
        if sort == 'seq':
            d['seq']['time'].append(float(time))
            d['seq']['num'].append(float(num))
        elif sort == 'ack':
            d['ack']['time'].append(float(time))
            d['ack']['num'].append(float(num))
        else:
            raise "Strange sort read while parse logging: %s" % sort


def save_graphs(attack):
    reserve_copy = True
    folder_out = GRPH_FLDR
    type_of_attck = attack

    if reserve_copy and type_of_attck not in ['div', 'dup', 'opt']:
        print("Attack mandatory cause save graphs")
        return

    cache_standart = {'seq': {'time': [], 'num': []}, 'ack': {'time': [], 'num': []}}
    attack_log = {'seq': {'time': [], 'num': []}, 'ack': {'time': [], 'num': []}}
    normal_f = open('cache.txt', 'r')
    attack_f = open('%s_cache_attack.txt' % type_of_attck, 'r')

    get_rows(normal_f, cache_standart)
    get_rows(attack_f, attack_log)

    if type_of_attck == 'div':
        info_of_attck = 'ACK Division'
    elif type_of_attck == 'dup':
        info_of_attck = 'DupACK Spoofing'
    elif type_of_attck == 'opt':
        info_of_attck = 'Optimistic ACKing'
    else:
        raise 'Unknown attack sort: %s' % type_of_attck
    standart_sequences_seconds, standart_sequences_no = cache_standart['seq']['time'], cache_standart['seq']['num']
    standart_seconds_acknwledges, standart_seconds_no = cache_standart['ack']['time'], cache_standart['ack']['num']
    sequences_attack_seconds, sequences_attack_no = attack_log['seq']['time'], attack_log['seq']['num']
    acknowledge_attack_seconds, acknowledge_attack_no = attack_log['ack']['time'], attack_log['ack']['num']
    schm.plot(standart_sequences_seconds, standart_sequences_no, 'b^', label='Default TCP Data Part')
    schm.plot(standart_seconds_acknwledges, standart_seconds_no, 'bx', label='Default TCP Acknowledges')
    schm.plot(sequences_attack_seconds, sequences_attack_no, 'rs', label='%s Cache Data Part' % info_of_attck)
    schm.plot(acknowledge_attack_seconds, acknowledge_attack_no, 'r+', label='%s Attack ACKs' % info_of_attck)
    schm.legend(loc='upper left')
    schm.xlim([0, max((max(standart_sequences_seconds), max(standart_seconds_acknwledges), \
                      max(sequences_attack_seconds), max(acknowledge_attack_seconds)))])
    schm.ylim([0, max((max(standart_sequences_no), max(standart_seconds_no), \
                      max(sequences_attack_no), max(acknowledge_attack_no)))])
    schm.xlabel('Time (s)')
    schm.ylabel('Sequence Number (Bytes)')

    if reserve_copy:
        if not os.path.exists(folder_out):
            os.makedirs(folder_out)
        schm.savefig(folder_out + "/" + type_of_attck)
    else:
        schm.show()

    normal_f.close()
    attack_f.close()

class CongestionTopo(Topo):
  def __init__(self):
    Topo.__init__(self)
    h1 = self.addHost('h1', ip='10.0.0.1')
    h2 = self.addHost('h2', ip='10.0.0.2')
    s1 = self.addSwitch('s1')
    self.addLink(h1, s1, bw=5, delay='50ms')
    self.addLink(h2, s1, bw=0.054, delay='50ms', max_queue_size=10)

class StandardTopo(Topo):
  def __init__(self, link_delay):
    Topo.__init__(self)
    h1 = self.addHost('h1', ip='10.0.0.1')
    h2 = self.addHost('h2', ip='10.0.0.2')
    s1 = self.addSwitch('s1')
    self.addLink(h1, s1, delay='%dms' % link_delay)
    self.addLink(h2, s1, delay='%dms' % link_delay)

topos = { 'standard' : (lambda: StandardTopo(250)),
          'congestion': (lambda: CongestionTopo())
        }

def main(data_size, num_attack, opt_interval, link_delay):
    topo = StandardTopo(link_delay)
    net = Mininet(topo=topo, host=CPULimitedHost, link=TCLink)
    net.start()
    dumpNodeConnections(net.hosts)
    drop_rate = net.pingAll()
    if drop_rate > 0:
        print
        'Accessibility test dropped Try again. '
        return

    h1 = net.get('h1')
    h2 = net.get('h2')


    rtt = 4 * link_delay
    print('Process delay  %.1f secs.' % (rtt / 1000.))


    time.sleep(2.)


    print('Begin usual TCP connecting')
    start_time = time.time()
    h2.sendCmd('python tcp_cong.py --role receiver --host h2')
    h1.sendCmd('python tcp_cong.py --role sender --host h1 --rtt %d --limit %d' \
               % (rtt, data_size))
    h2.waitOutput()
    h1.waitOutput()
    print('Usual TCP connecting finish (%.2f sec)' % (time.time() - start_time))

    time.sleep(2.)


    print('Begin Acknowledge Div cache')
    start_time = time.time()
    h2.sendCmd('python ack.py --host h2 --attack div --num %d' % num_attack)
    h1.sendCmd('python tcp_cong.py --role sender --host h1 --rtt %d --limit %d' \
               % (rtt, data_size))
    h2.waitOutput()
    h1.waitOutput()
    h2.cmd('mv cache_attack.txt div_cache_attack.txt')
    print('Div attack finish! (%.2f sec)' % (time.time() - start_time))

    time.sleep(2.)


    print('Begin Dup attack!')
    start_time = time.time()
    h2.sendCmd('python ack.py --host h2 --attack dup --num %d' % num_attack)
    h1.sendCmd('python tcp_cong.py --role sender --host h1 --rtt %d --limit %d' \
               % (rtt, data_size))
    h2.waitOutput()
    h1.waitOutput()
    h2.cmd('mv cache_attack.txt dup_cache_attack.txt')
    print('Dup Spoofing attack done! (%.2f sec)' % (time.time() - start_time))

    time.sleep(2.)


    print('Begin Opt attack!')
    start_time = time.time()
    h2.sendCmd('python ack.py --host h2 --attack opt --num %d --interval %d' \
               % (num_attack, opt_interval))
    h1.sendCmd('python tcp_cong.py --role sender --host h1 --rtt %d --limit %d' \
               % (rtt, data_size))
    h2.waitOutput()
    h1.waitOutput()
    h2.cmd('mv cache_attack.txt opt_cache_attack.txt')
    print('Opt attacking finish. (%.2f sec)' % (time.time() - start_time))

    net.stop()


if __name__ == "__main__":
    if not os.path.exists(GRPH_FLDR):
        os.mkdir(GRPH_FLDR)
    link_delay = 375
    default_delay = 250
    data_size = 60
    num_attack = 50
    opt_interval = 20
    main(link_delay=link_delay, data_size=data_size, num_attack=num_attack, opt_interval=opt_interval)
    save_graphs("div")
    save_graphs("dup")
    save_graphs("opt")
    print 'Saved'
