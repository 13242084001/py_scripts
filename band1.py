#!/usr/bin/env python3.6
#
import subprocess
import time
from collections import deque
from functools import reduce
import gol
import netifaces
from IPy import IP
import threading
import curses
import os
from pyroute2 import IPRoute,protocols
import socket
import getopt
import sys
import ipaddress
from prettyprinter import cpprint
from signal import signal, SIGINT


last = [0,0]
is_active = True
#gol._init()

class GetIfaces(object):

    def __init__(self):
        self.nic_list = netifaces.interfaces()
        self.nic_list.remove('lo')
        self.interfaces_dict = {}
        self.nic_interface_info()

    def nic_interface_info(self):
        for nic in self.nic_list:
            net_info_list = netifaces.ifaddresses(nic)[netifaces.AF_INET]
            #print("this is net_info_list %s" % net_info_list)
            addr = net_info_list[0]["addr"]
            netmask = net_info_list[0]["netmask"]
            hosts = self.get_net_hosts(addr, netmask)
            self.interfaces_dict[nic] = {"addr": addr, "netmask": netmask, "hosts": hosts}

    def get_gateway(self):
        ipv4_gateway_list = netifaces.gateways()[netifaces.AF_INET]
        for tup in ipv4_gateway_list:
            pass
            #if self.nic in tup:
            #    return tup[0]

    def get_net_hosts(self, addr, netmask):
        return IP(addr).make_net(netmask)

    def get_nic(self, nic_ip):
        for nic in self.nic_list:
            addr = netifaces.ifaddresses(nic)[netifaces.AF_INET][0].get("addr")
            #print('######%s' % addr)
            if nic_ip == addr:
                return nic

def usage():
    print('Usage: -h help \n'
            '       -d destination ip address\n'
            '       -s source ip address\n'
            '       -i interface\n'
            '       -r rate bitrate\n'
            '       -f flush tc qdisc\n'
            '       -l loss rate\n'
            '       -D delay\n'
            )

def args(usage):
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hfd:s:i:r:l:D:", ['help', 'flush', 'dst=', 'src=', 'interface=', 'rate=', 'loss=', 'delay='])
        options_dict = {}
        for k, v in opts:
            if k in ('-h', '--help'):
                usage()
                os._exit(0)
            elif k in ('-f', '--flush'):
                interface = options_dict.get('interface')
                options_dict.clear()
                options_dict['interface'] = interface
                options_dict['flush'] = True
                return options_dict
            elif k in ('-d', '--dst'):
                options_dict['dst'] = v
            elif k in ('-s', '--src'):
                options_dict['src'] = v
            elif k in ('-i', '--interface'):
                options_dict["interface"] = v
            elif k in ('-r', "--rate"):
                options_dict["rate"] = v
            elif k in ('-l', '--loss'):
                options_dict["loss"] = int(v)
            elif k in ('-D', '--delay'):
                options_dict['delay'] = int(v)
        return options_dict
    except Exception as e:
        print(str(e))
        usage()
        os._exit(0)
    
def get_mcu_ip():
    #这是你要获取的那个进程
    cmd = "netstat -antp|awk '{print $4,$5}'|grep 1089|head -1"
    out = subprocess.getstatusoutput(cmd)
    if not out[0] and out[1]:
    #return ["192.168.0.102", "192.168.0.10"]
        #print('*************%s' % out[1].split())
        return [x.split(':')[0] for x in out[1].split()]

class tc_handle(object):
    
    def __get_default_dst():
	#目的地址
        """
        out = subprocess.getstatusoutput("netstat -antp|grep -w 1089|awk '{print $5}'|head -n 1|cut -d: -f1")
        if not out[0]:
            #print(out[1])
            return out[1]
        """
        return get_mcu_ip()[1] if get_mcu_ip() else None
		
    def __init__(self, dst=__get_default_dst(), src=None, interface=None, rate='500', flush=False, loss=0, delay=0):
        self.ip = IPRoute()
        self.rate = rate
        self.nic = self.ip.link_lookup(ifname=interface if interface else 'eth0')[0]
        #print('nic is %s'% (self.nic))
        self.flush = flush
        self.loss = loss
        self.delay = delay
        if not self.flush:
            if dst != None and src == None:
                filter_addr_tp = ('dst', dst)
            elif src != None and dst == None:
                filter_addr_tp = ('src', src)
            else:
                filter_addr_tp = None
            flag, self.filter_addr = (None, self.ip.get_addr(label=interface)[0].get('attrs')[0][1]) if not filter_addr_tp else filter_addr_tp
            #print(self.filter_addr, self.rate)
            self.keys = self.v4_hex(self.filter_addr, flag)
            #print(self.keys)
            #print(self.nic)
    
    def v4_hex(self, dict_str, flag):
        flags = '+12' if flag == 'src' else '+16'
        #print('flags %s' % flags)
        try:
            dst_ip_str = IP(dict_str).strNormal(2) if len(dict_str.split('/')) > 1 else dict_str + '/255.255.255.255'
            #dst_net, mask = dst_ip_str.split('/')
            #print(dst_ip_str)
            try:
                keys = ['/'.join([str(hex(int(ipaddress.IPv4Address(i)))) for i in dst_ip_str.split('/')]) + flags]
                #print('this is key %s' % keys)

            except Exception as e:
                #print("ip is not available!")
                os._exit(0)
            return keys
        except Exception as e:
            print(str(e))
            os._exit(0)

    def flush_instance(self):
        try:
            self.ip.tc('del', 'htb', self.nic, 0x10000)
        except Exception as e:
            pass
    """
    def only_rate_limit(self):
        self.ip.tc('add', 'tbf', self.nic, 0x100000, parent=0x10010, rate=self.rate+'kbit', burst=1024 * 2, latency='200ms')

    def only_no_rate_limit(self):
        self.ip.tc('add', 'netem', self.nic, 0x100000, parent=0x10010, loss=30)
    """
    def __call__(self):
        self.flush_instance()
        if not self.flush:
            self.ip.tc('add', 'htb', self.nic, 0x10000, default=0x200000)
            self.ip.tc('add-class', 'htb', self.nic, 0x10001, parent=0x10000, rate='1000mbit', prio=4)
            #print(self.rate)
            self.ip.tc('add-class', 'htb', self.nic, 0x10010, parent=0x10001, rate=self.rate+'kbit',prio=3)
            self.ip.tc('add-class', 'htb', self.nic, 0x10020, parent=0x10001, rate='700mbit', prio=2)
            if self.loss or self.delay:
                #print(self.delay)
                self.ip.tc('add', 'netem', self.nic, 0x100000, parent=0x10010, loss=self.loss, delay=self.delay)
            else:
                self.ip.tc('add', 'tbf', self.nic, 0x100000, parent=0x10010, rate=self.rate+'kbit', burst=1024 * 2, latency='200ms')
            self.ip.tc('add', 'sfq', self.nic, 0x200000, parent=0x10020, perturb=10)
            #pyroute2 有bug，对socket家族的协议解析有不正确的地方，比如AF_INET应该解析成IPV4,但是解析成了ax25,AF_AX25解析成了all,所以将错就错用这个好了,protocols也一样的结果
            self.ip.tc('add-filter', 'u32', self.nic, parent=0x10000, prio=1, protocol=socket.AF_AX25, target=0x10010, keys=self.keys)



def check_iptables(mcu_ip):
    cmd1 = "iptables -L INPUT --line-number|grep %s|awk '{print $1}'" % mcu_ip
    cmd2 = "iptables -L OUTPUT --line-number|grep %s|awk '{print $1}'" % mcu_ip
    iptables_dict = {}
    for cmd in (cmd1, cmd2):
        out = subprocess.getstatusoutput(cmd)
        if not out[0] and out[1]:
            if 'input_list' in iptables_dict:
                iptables_dict["output_list"] = out[1].split("\n")
            else:
                iptables_dict["input_list"] = out[1].split("\n")
    #print('this is %s' % iptables_dict)
    for k, v in iptables_dict.items():
        v.reverse()
        if "input_list" == k:
            #print('zheshi %s' % v)
            #print(11111111)
            for num in v:
                subprocess.getstatusoutput("iptables -D INPUT %s" % num)
        elif "output_list" == k:
            for num in v:
                subprocess.getstatusoutput("iptables -D OUTPUT %s" % num)

def exec_iptables_cmd(mcu_ip):
    check_iptables(mcu_ip)
    cmd1 = "iptables -I INPUT -s %s" % mcu_ip
    cmd2 = "iptables -I OUTPUT -d %s" % mcu_ip
    #print(222222)
    for cmd in (cmd1, cmd2):
        out = subprocess.getstatusoutput(cmd)
        if not out[0]:
            pass
        else:
            #print(out[1])
            pass

def bandwidth():
    """
    获取到特定ip的流量，bytes，返回一个数组，进入的bytes数，发出的bytes数；[234.11,2233.33]
    """
    cmd = "iptables -nvxL|grep %s|awk '{print $2}'" % gol.get_value("mcu_ip")
    out = subprocess.getstatusoutput(cmd)
    if not out[0]:
        st = map(lambda x: int(x) * 8 / 1000, out[1].split())
        #print(st)
        return list(st)

def calc(after, last):
    time.sleep(1)
    new_last = after()
    result = list(map(lambda x, y: x-y, new_last, last))
    #print(result)
    return result, new_last

def data_queue(calc, a, b):
    dq = deque(maxlen=10)
    while True:
        #if is_active:
            #print('this is %s' % b)
        result, b = calc(a, b)
        dq.append(result)
        yield dq
        #else:
            #print(111111111111111)
            #break
        
def add(x, y):
    return list(map(lambda a, b: a+b, x,y))

def get_network_status():
    #print(gol._global_dict)
    out = subprocess.getstatusoutput("ping %s -f -c 10" % gol.get_value("mcu_ip"))
    #print(out)
    if not out[0]:
        re = out[1].split(',')[2:]
        gol.set_value("packet loss", re[0].split()[0])
        gol.set_value(re[1].split(' = ')[0].split('\n')[1], re[1].split(' = ')[1])
        #print(gol._global_dict)


def exec():
    nic_ip, mcu_ip = get_mcu_ip()
    iface_obj = GetIfaces()
    nic = iface_obj.get_nic(nic_ip)
    gol.set_value('mcu_ip', mcu_ip)
    gol.set_value('nic_ip', nic_ip)
    gol.set_value('nic', nic)
    exec_iptables_cmd(mcu_ip)
    time.sleep(1)
    for dq in data_queue(calc, bandwidth, last):
        tmp_list = list(dq)
        #print(tmp_list)
        avg10 = list(map(lambda x: round(x / 10, 2), reduce(add, tmp_list)))
        avg2 = list(map(lambda x: round(x / 2, 2), reduce(add, tmp_list[-2:])))
        avg5 = list(map(lambda x: round(x / 5, 2), reduce(add, tmp_list[-5:])))
        get_network_status()
        gol.set_value('avg10', avg10)
        gol.set_value('avg2', avg2)
        gol.set_value('avg5', avg5)
        #print(gol._global_fict)
        #print('\r', gol._global_dict, end='')
        #print('\r', avg5, end='')

def prettyPrint():
    str1 = 'Interface: %s' % (gol.get_value('nic'))
    str2 = 'IP Address is: %s' % (gol.get_value('nic_ip'))
    str3 = '='*(int(width)-2)
    lenStr4 = int(width)-2
    str4_1 = ' '*(lenStr4//2)
    str4_2 = 'last2sec'
    str4_3 = ' '*(lenStr4//6 - len(str4_2))
    str4_4 = 'last5sec'
    str4_5 = str4_3
    str4_6 = 'last10sec'
    str4 = str4_1 + str4_2 + str4_3  + str4_4 + str4_5 + str4_6
    str5_1 = str4_1
    str5_2 = gol.get_value('nic_ip')
    str5_3 = ' '*(lenStr4//4 - len(str5_2))
    str5_4 = '===>   '
    str5_5 = gol.get_value('mcu_ip')
    str5_6 = ' '*(lenStr4//4 + 1 - len(str5_4 + str5_5))
    #print(gol._global_dict)
    str5_7 = str(gol.get_value('avg2')[1]) + 'kbps'
    str5_8 = ' '*(lenStr4//6 - len(str5_7))
    str5_9 = str(gol.get_value('avg5')[1]) + 'kbps'
    str5_10 = ' '*(lenStr4//6 - len(str5_9))
    str5_11 = str(gol.get_value('avg10')[1]) + 'kbps'
    str5 = str5_2 + str5_3 + str5_4 + str5_5 + str5_6 + str5_7 + str5_8 + str5_9 + str5_10 + str5_11
    str6_1 = ' '*(lenStr4//4) + '<==='
    str6_2 = ' '*((lenStr4//2) - len(str6_1))
    str6_3 = str(gol.get_value('avg2')[0]) + 'kbps'
    str6_4 = ' '*(lenStr4//6 - len(str6_3))
    str6_5 = str(gol.get_value('avg5')[0]) + 'kbps'
    str6_6 = ' '*(lenStr4//6 - len(str6_5))
    str6_7 = str(gol.get_value('avg10')[0]) + 'kbps'
    str6 = str6_1 + str6_2 + str6_3 + str6_4 + str6_5 + str6_6 + str6_7
    str7 = ' '
    str8_1 = 'rtt min/avg/max/mdev'
    str8_2 = ' '*(lenStr4//2 - len(str8_1))
    str8_3 = 'packet loss'
    str8 = str8_1 + str8_2 + str8_3
    str9_1 = gol.get_value('rtt min/avg/max/mdev')
    str9_2 = ' '*(lenStr4//2 - len(str9_1))
    str9_3 = gol.get_value('packet loss')
    str9 = str9_1 + str9_2 + str9_3
    str10 = ' '
    return str1,str2,str3,str4,str5,str6,str7,str8,str9,str10

class init_scr(object):
    #_instance = None
    """
    __stdscr = None

    def __new__(cls, *args, **kwargs):
        print(cls.__stdscr)
        if not cls.__stdscr:
            print(False)
            cls.__stdscr = None
            print(cls.__stdscr)
        print(cls.__stdscr)
        return cls.__stdscr
    """

    def __init__(self):
        """
        if self.__stdscr:
            print(111)
            self.endWin()
        """
        self.__stdscr = curses.initscr()
        curses.noecho()
        curses.cbreak()
        #print(222)
        self.__stdscr.keypad(1)
        self.__stdscr.box()
        global width, height
        width = os.get_terminal_size().columns
        height = os.get_terminal_size().lines
        self.c_y = height//2 - 1
        self.c_x = width//2 - 10

    def __call__(self):
        self.__stdscr.addstr(self.c_y + 5, self.c_x, 'Press y to continue', curses.A_REVERSE)
        while True:
            #stdscr.refresh()
            y = self.__stdscr.getch()
            if y in (ord('y'), ord('Y')):
                #curses.endwin()
                self.__stdscr.clear()
                break
    
        while True:
            #if is_active:
            self.__stdscr.box()
            str_list = prettyPrint()
            for i, value in enumerate(str_list):
                self.__stdscr.addstr(i+1, 1, value)
            self.__stdscr.refresh()
            time.sleep(1)

    def endWin(self):
        #print(self.__stdscr)
        self.__stdscr.keypad(0)
        curses.echo()
        curses.nocbreak()
        curses.endwin()

def main():
    signal(SIGINT, signal_handle)
    options_dict = args(usage)
    cpprint(options_dict)
    tc_handle(**options_dict)()
    gol._init()
    t = threading.Thread(target=exec, args=())
    t.setDaemon(True)
    t.start()
    time.sleep(2)
    global win
    win = init_scr()
    win()

def signal_handle(signum, frame):
    is_active = False
    win.endWin()
    sys.exit(signum)

if __name__ == "__main__":
    main()

