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

#消息头字段，表示空消息，什么都不做
NLMSG_NOOP = 1
#消息头字段nkmsg_type中的一种，表示该消息中包含一个错误
NLMSG_ERROR = 2
#链路相关，新增链路
RTM_NEWLINK = 16
#删除链路
RTM_DELLINK = 17
"""
#获取链路信息
RTM_GETLINK
#设置链路
RTM_SETLINK
"""
RTM_NEWADDR = 20

RTM_DELADDR = 21


RTM_NEWROUTE = 24

RTM_DELROUTE = 25

RTM_GETROUTE = 26

IFLA_IFNAME = 3

def get_ipv4_ip(hex_ip):
    return ".".join([str(int(i, 16)) for i in re.findall(r'.{2}', hex_ip)])

# Create the netlink socket and bind to RTMGRP_LINK,
s = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, socket.NETLINK_ROUTE)
#s.bind((os.getpid(), RTMGRP_LINK))
#s.bind((os.getpid(), RTMGRP_IPV4_IFADDR))
#s.bind((os.getpid(), RTMGRP_IPV4_ROUTE))
s.bind((os.getpid(), RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE))

while True:
    data = s.recv(65535)
    #print(type(data))
    #print(data)
    #消息头字段，消息总长度，消息类型（数据或控制消息，附加在消息上额外说明信息，消息序列号，内核主动发起时，seq总为0，为每一个进程-内核通信会话分配通道唯一标识）
    msg_len, msg_type, flags, seq, pid = struct.unpack("=LHHLL", data[:16])
    #print(msg_len, msg_type, flags, seq, pid)
    #nlmsg_noop,什么都不做
    if msg_type == NLMSG_NOOP:
        print("no-op")
        continue
    #消息中包含一个错误
    elif msg_type == NLMSG_ERROR:
        print("error")
        break
    
    #print(msg_type)
    # We fundamentally only care about NEWLINK messages in this version.
    #
    
    if msg_type == RTM_NEWLINK:
        #continue
    
        data = data[16:]

        family, _, if_type, index, flags, change = struct.unpack("=BBHiII", data[:16])
        #print(family, _, if_type, index, flags, change)
        remaining = msg_len - 32
        data = data[16:]
        #print('######', remaining)
        while remaining:
            rta_len, rta_type = struct.unpack("=HH", data[:4])

        # This check comes from RTA_OK, and terminates a string of routing
        # attributes.
            if rta_len < 4:
                break

            rta_data = data[4:rta_len]
            #print(rta_data)
            #print('is ssss %s'% rta_len)
            increment = (rta_len + 4 - 1) & ~(4 - 1)
            #print(increment)
            #32字符以后,
            data = data[increment:]
            #print('data is %s' % data)
            remaining -= increment

            # Hoorah, a link is up!
            #print rta_type
            if rta_type == IFLA_IFNAME:
                print("nic is %s" % rta_data.decode())
            elif rta_type == 1:
                print('mac addr is %s' % rta_data.hex())
            elif rta_type == 4:
                print('mtu is %s' % struct.unpack('I', rta_data))
            elif rta_type == 6:
                print('qdisc is %s' % rta_data.decode())
            elif rta_type == 2:
                print('broadcast addr is %s' % rta_data.hex())

    if msg_type in (RTM_NEWADDR, RTM_DELADDR):
        #print("###########################")
        data = data[16:]

        family, prefixlen, flags, scope, index = struct.unpack("=BBBBi", data[:8])
        #print(family, prefixlen, flags, scope, index)
        remaining = msg_len - 24
        data = data[8:]
        #print('######', remaining)
        while remaining:
            rta_len, rta_type = struct.unpack("=HH", data[:4])

        # This check comes from RTA_OK, and terminates a string of routing
        # attributes.
            if rta_len < 4:
                break

            rta_data = data[4:rta_len]
            #print(rta_data)
            #print('is ssss %s'% rta_len)
            increment = (rta_len + 4 - 1) & ~(4 - 1)
            #print(increment)
            #32字符以后,
            data = data[increment:]
            #print('data is %s' % data)
            remaining -= increment

            # Hoorah, a link is up!
            #print rta_type
            if rta_type == 1:
                #print("IP is %s" % rta_data.hex())
                hex_ip = rta_data.hex()
                tp_li = get_ipv4_ip(hex_ip)
                print('ip addr is %s' % tp_li)
    
    if msg_type in (RTM_NEWROUTE, RTM_DELROUTE):
        tips_dict = {RTM_NEWROUTE: 'ADD ROUTE ', RTM_DELROUTE: 'DELETE ROUTE'}
        print(tips_dict.get(msg_type))
        rt_params = {1: 'route destination ip addr', 2: 'route source ip addr', 3: 'input interface index', 4: 'output intetface index', 5: 'getway ip addr', 6: 'route priority'}
        #print("###########################")
        data = data[16:]

        family, dst_len, src_len, tos, rt_table, rt_protocol, rt_scope, rtm_type, flags = struct.unpack("=BBBBBBBBI", data[:12])
        #print(family, dst_len, src_len, tos, rt_table, rt_protocol, rt_scope, rtm_type, flags)
        remaining = msg_len - 28
        data = data[12:]
        #print('######', remaining)
        while remaining and rt_table == 254:
            rta_len, rta_type = struct.unpack("=HH", data[:4])

        # This check comes from RTA_OK, and terminates a string of routing
        # attributes.
            if rta_len < 4:
                break

            rta_data = data[4:rta_len]
            #print(rta_data)
            #print('is ssss %s'% rta_len)
            increment = (rta_len + 4 - 1) & ~(4 - 1)
            #print(increment)
            #32字符以后,
            data = data[increment:]
            #print('data is %s' % data)
            remaining -= increment

            # Hoorah, a link is up!
            #print('rta_type is %s' % rta_type)
            #print(len(rta_data))
            if rt_params.get(rta_type):
                if rta_type in (1, 2, 5):
                    print(rt_params.get(rta_type), get_ipv4_ip(rta_data.hex()))
                    #print(rt_params.get(rta_type), rta_data)
                else:
                    print(rt_params.get(rta_type), struct.unpack('I', rta_data)[0])
    else:
        continue

