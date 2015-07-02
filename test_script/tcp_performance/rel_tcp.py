#!/usr/bin/python

from mininet.topo import Topo
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.net import Mininet
from mininet.log import lg, info
from mininet.util import dumpNodeConnections
from mininet.cli import CLI

from subprocess import Popen, PIPE
from time import sleep, time
from multiprocessing import Process
from argparse import ArgumentParser

import sys
import os

# Parse arguments

parser = ArgumentParser(description="Reliable TCP simulation")
parser.add_argument('--bw-host', '-B',
                    dest="bw_host",
                    type=float,
                    action="store",
                    help="Bandwidth of host links (Mbps)",
                    default=1.5)

parser.add_argument('--delay',
                    dest="delay",
                    type=float,
                    help="Delay in milliseconds of host links",
                    default=10)

parser.add_argument('--loss',
                    dest="loss",
                    type=int,
                    help="Packet loss of host links",
                    default=5)

parser.add_argument('--dir', '-d',
                    dest="dir",
                    action="store",
                    help="Directory to store outputs",
                    default="results")

parser.add_argument('--port', '-p',
                    dest="port",
                    action="store",
					type=int,
                    help="Base port of transmission",
                    default=5000)

parser.add_argument('--maxq',
                    dest="maxq",
                    action="store",
                    help="Max buffer size of network interface in packets",
                    default=2)

parser.add_argument('--filename', '-f',
                    dest="filename",
                    action="store",
                    help="File that will be transmitted",
                    default="landscape.jpg")

parser.add_argument('--case',
                    dest="case",
                    type=int,
                    action="store",
                    help="Case numner -- for file name",
                    default=1)
# Expt parameters
args = parser.parse_args()


class StarTopo(Topo):
    "Star topology for Buffer Bloat experiment"

    def __init__(self, n=2, cpu=None, bw_host=1.5,
                 delay=10, loss=5, maxq=2):
        # Add default members to class.
        super(StarTopo, self ).__init__()

        print 'StartTopo loss is %s, delay is %s' % (loss, delay)

        # Create switch and host nodes
        for i in xrange(n):
            self.addHost( 'h%d' % (i+1), cpu=cpu )

        self.addSwitch('s0', fail_mode='open')

        for i in xrange(n):
            self.addLink('h%d' % (i+1), 's0', bw=bw_host, delay=delay,loss=int(loss, 10),
                max_queue_size=int(maxq))

def test_relsend():
    "Create network and run reliable transport experiment"
    print "starting mininet ...."
    seconds = 3600
    start = time()
    # Reset to known state
    topo = StarTopo( bw_host=args.bw_host,
                    delay='%sms' % args.delay,
					loss='%s' % args.loss,
                   maxq=args.maxq)
    print 'Loss is %s, delay is %s, buffer size is %s, port number is %d, filename is %s, case is %d' % (args.loss, args.delay, args.maxq, args.port, args.filename, args.case)
    net = Mininet(topo=topo, host=CPULimitedHost, link=TCLink)
                  
    net.start()
    h2 = net.getNodeByName('h2')
    h1 = net.getNodeByName('h1')
    h1ip = h1.IP()
    h2ip = h2.IP()
    print "running experiment"
    now = time()
    h1.cmd('./hw7_receiver %d > RECVD_FILE%s 2> /dev/null &' % (args.port, args.case))
    h2.cmd('cat %s | ./hw7_sender %s %d 2> sender_output%s &' % (args.filename, h1ip, args.port, args.case))
    h2.cmd('wait')
    elapsed = time() - now
    print "finished experiment in %s sec"%  str(elapsed)
#resultmd5 = h1.cmd('md5sum RECVD_FILE%s' % args.case).split()[0]
#    print "resulting file has md5 sum %s" % resultmd5

    # this will drop you to a mininet shell if you need it
    # CLI( net )    
    net.stop()

if __name__ == '__main__':
    test_relsend()
