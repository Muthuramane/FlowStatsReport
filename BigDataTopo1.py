#!/usr/bin/python

# Copyright 2013-present Barefoot Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

##############################################################################
# Topology with two switches and two hosts with static routes
#
#       2ffe:0101::/64          2ffe:0010::/64         2ffe:0102::/64
#       172.16.101.0/24         172.16.10.0/24         172.16.102.0./24
#  h1 ------------------- sw1 ------------------ sw2------- -------------h2
#     .5               .1     .1               .2   .1                  .5
##############################################################################

from mininet.net import Mininet, VERSION
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.node import RemoteController
from distutils.version import StrictVersion
from time import sleep
import sys

def main(cli=0, ipv6=0):
    hosts = []
    #switches = []
    #net = Mininet( controller = None )
    net = Mininet(controller=lambda a: RemoteController( a, ip='10.211.55.4', port=6633 ))

    c0 = net.addController('c0', controller=RemoteController,ip='10.211.55.4',port=6633)

    # add hosts
    for h in range(1, 5):
        hosts.append(net.addHost('h%s'%h))

    sw1 = net.addSwitch('s1')


    #for s in range(1, 5):
    #    switches.append(net.addSwitch('s%s'%s))

    port = 1
    for host in hosts:
        net.addLink(sw1, host, port1=port)
        port=port+1


    net.start()

    CLI( net )
    
    net.stop()


if __name__ == '__main__':
    args = sys.argv
    setLogLevel( 'info' )
    cli = 0
    ipv6 = 0

    main(cli, ipv6)
