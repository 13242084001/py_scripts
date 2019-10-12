#!/usr/bin/env python3.6
#
import os
import socket
import struct
import re


# These constants map to constants in the Linux kernel. This is a crappy
# way to get at them, but it'll do for now.
RTMGRP_LINK = 1

RTMGRP_IPV4_IFADDR = 16

RTMGRP_IPV4_ROUTE = 64

# 消息头字段，表示空消息，什么都不做
NLMSG_NOOP = 1
# 消息头字段nkmsg_type中的一种，表示该消息中包含一个错误
NLMSG_ERROR = 2
# 链路相关，新增链路
RTM_NEWLINK = 16
# 删除链路
RTM_DELLINK = 17
"""
#获取链路信息
RTM_GETLINK = 18
#设置链路
RTM_SETLINK = 19
"""
RTM_NEWADDR = 20

RTM_DELADDR = 21

RTM_NEWROUTE = 24

RTM_DELROUTE = 25

RTM_GETROUTE = 26

IFLA_IFNAME = 3

second_header_len_dict = {'link': 16, 'ifaddr': 8, 'route': 12}
    
rt_params = {1: 'route destination ip addr', 2: 'route source ip addr', 3: 'input interface index', 4: 'output intetface index', 5: 'getway ip addr', 6: 'route priority'}
    
tips_dict = {RTM_NEWROUTE: 'ADD ROUTE ', RTM_DELROUTE: 'DELETE ROUTE', RTM_NEWLINK: 'ADD LINK', RTM_DELLINK: 'DELETE LINK', RTM_NEWADDR: 'ADD ADDRESS', RTM_DELADDR: 'DELETE ADDRESS'}


def get_ipv4_ip(hex_ip):
    return ".".join([str(int(i, 16)) for i in re.findall(r'.{2}', hex_ip)])


class NetStat(object):
	
    def __init__(self):

        # Create the netlink socket and bind to RTMGRP_LINK,
        self.s = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, socket.NETLINK_ROUTE)
        #s.bind((os.getpid(), RTMGRP_LINK))
        #s.bind((os.getpid(), RTMGRP_IPV4_IFADDR))
        #s.bind((os.getpid(), RTMGRP_IPV4_ROUTE))
        self.s.bind((os.getpid(), RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE))

    def common_handle(self):
        layer = self.layer_dispatch()
        layer_header_len = second_header_len_dict.get(layer)
        remaining = self.msg_len - 16 - layer_header_len
        data = self.data[layer_header_len:]
        # print('######', remaining)
        while remaining:
            self.rta_len, self.rta_type = struct.unpack("=HH", data[:4])

            # This check comes from RTA_OK, and terminates a string of routing
            # attributes.
            if self.rta_len < 4:
                break
            self.rta_data = data[4:self.rta_len]
            # print(rta_data)
            # print('is ssss %s'% rta_len)
            increment = (self.rta_len + 4 - 1) & ~(4 - 1)
            # print(increment)
            # 32字符以后,
            data = data[increment:]
            # print('data is %s' % data)
            remaining -= increment
            getattr(NetStat, layer)(self)

    def link(self):
        if self.rta_type == IFLA_IFNAME:
            print("nic is %s" % self.rta_data.decode())
        elif self.rta_type == 1:
            print('mac addr is %s' % self.rta_data.hex())
        elif self.rta_type == 4:
            print('mtu is %s' % struct.unpack('I', self.rta_data))
        elif self.rta_type == 6:
            print('qdisc is %s' % self.rta_data.decode())
        elif self.rta_type == 2:
            print('broadcast addr is %s' % self.rta_data.hex())

    def ifaddr(self):
        if self.rta_type == 1:
            # print("IP is %s" % rta_data.hex())
            hex_ip = self.rta_data.hex()
            tp_li = get_ipv4_ip(hex_ip)
            print('ip addr is %s' % tp_li)

    def route(self):
        if rt_params.get(self.rta_type):
            if self.rta_type in (1, 2, 5):
                print(rt_params.get(self.rta_type), get_ipv4_ip(self.rta_data.hex()))
                # print(rt_params.get(rta_type), rta_data)
            else:
                print(rt_params.get(self.rta_type), struct.unpack('I', self.rta_data)[0])

    def layer_dispatch(self):
        print(tips_dict.get(self.msg_type) if tips_dict.get(self.msg_type) else '')
        if self.msg_type in (RTM_NEWLINK, RTM_DELLINK):
            return 'link'
        elif self.msg_type in (RTM_NEWADDR, RTM_DELADDR):
            return 'ifaddr'
        elif self.msg_type in (RTM_NEWROUTE, RTM_DELROUTE):
            return 'route'

    def __call__(self):
        while True:
            data = self.s.recv(65535)
            #print(type(data))
            #print(data)
            #消息头字段，消息总长度，消息类型（数据或控制消息，附加在消息上额外说明信息，消息序列号，内核主动发起时，seq总为0，为每一个进程-内核通信会话分配通道唯一标识）
            self.msg_len, self.msg_type, self.flags, self.seq, self.pid = struct.unpack("=LHHLL", data[:16])
            self.data = data[16:]
            print(self.msg_type)
            #nlmsg_noop,什么都不做
            if self.msg_type == NLMSG_NOOP:
                print("no-op")
                continue
            #消息中包含一个错误
            elif self.msg_type == NLMSG_ERROR:
                print("error")
                break

            #print(msg_type)
            self.common_handle()

if __name__ == '__main__':
	NetStat()()
