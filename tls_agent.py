#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
    :copyright: (c) 2022 by Wsq.
    :license: MIT, see LICENSE for more details.
"""

import os
import sys
import ssl
import time
import json
import socket
import select
#import argparse
import threading

def debug(tag, msg):
    print('[%s] %s' % (tag, msg))


class TlsProxyThread(threading.Thread):
    def __init__(self, host='0.0.0.0', port=443, listen=10, bufsize=8, delay=1,server_host="127.0.0.1",server_port=None,tls=True,server_key=None,server_cert=None,server_cacert=None,client_key=None,client_cert=None):
        threading.Thread.__init__(self)
        self.server_host = server_host
        self.server_port = server_port
        self.socket_proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket_proxy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # 将SO_REUSEADDR标记为True, 当socket关闭后，立刻回收该socket的端口
        try:
            self.socket_proxy.bind((host, port))
        except OSError as e:
            debug('error','(%s,%s) Address or port refuse to be used!' % (host, port))
            sys.exit(-1)
        self.socket_proxy.listen(listen)

        self.socket_recv_bufsize = bufsize*1024
        self.delay = delay/1000.0
        self.tls = tls
        self.server_keyfile = server_key
        self.server_certfile = server_cert
        self.server_cacertfile = server_cacert
        self.client_keyfile = client_key
        self.client_certfile = client_cert

    def __del__(self):
        self.socket_proxy.close()
    
    def __connect(self, host, port,):
        '''
        解析DNS（如果是域名方式请求）得到套接字地址并与之建立连接
        参数：host 主机
        参数：port 端口
        返回：与目标主机建立连接的套接字
        '''
        # 解析DNS获取对应协议簇、socket类型、目标地址
        # getaddrinfo -> [(family, sockettype, proto, canonname, target_addr),]
        (family, sockettype, _, _, target_addr) = socket.getaddrinfo(host, port)[0]
        
        tmp_socket = socket.socket(family, sockettype)
        tmp_socket.setblocking(0)
        tmp_socket.settimeout(8)
        tmp_socket.connect(target_addr)
        if self.tls == True:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            try:
                # 此处不校验SSL服务器server_hostname信息
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                #context.load_verify_locations(c)
                context.load_cert_chain(certfile=self.client_certfile, keyfile=self.client_keyfile)
                socket_client_tls = context.wrap_socket(tmp_socket, server_side=False)
            except Exception as e:
                debug('error',e)
            return socket_client_tls
        return tmp_socket
         
    def __proxy(self, socket_client):
        '''
        代理核心程序
        参数：socket_client 代理端与客户端之间建立的套接字
        '''
        # 接收客户端请求数据
        req_data = socket_client.recv(self.socket_recv_bufsize)
        print("############raw:#############\n","get a request\n%s" %req_data)
        if req_data == b'':
            debug("debug","None data...")
            return

        # 定义服务器套接字列表和select套接字列表
        socket_server_list = []
        socket_list = []

        print(self.server_host)
        #  接收命令行传入的server_host和server_port
        #  此处可以设置全局变量接收其他线程发来的server_host替换self.server_host
        for server_host in self.server_host:
            socket_server = self.__connect(server_host, self.server_port) # 与server建立连接
            socket_server_list.append(socket_server)
            socket_list.append(socket_server)
            socket_server.send(req_data)
        
        # 使用select异步处理，不阻塞
        socket_list.append(socket_client)
        print(socket_list)
        if len(socket_list) < 2:
            debug("debug","not client or server")
            return
        self.__nonblocking(socket_client,socket_server_list,socket_list)

    def __nonblocking(self,socket_client,socket_server_list,socket_list):
        '''
        使用select实现异步处理数据
        参数：socket_client 代理端与客户端之间建立的套接字
        参数：socket_server_list 代理端与服务端（可以多台）之间建立的套接字
        '''
        _rlist = socket_list
        is_recv = True
        timeout_select = 4
        while is_recv:
            try:
                # rlist, wlist, elist = select.select(_rlist, _wlist, _elist, [timeout])
                # 参数1：当列表_rlist中的文件描述符fd状态为readable时，fd将被添加到rlist中
                # 参数2：当列表_wlist中存在文件描述符fd时，fd将被添加到wlist
                # 参数3：当列表_xlist中的文件描述符fd发生错误时，fd将被添加到elist
                # 参数4：超时时间timeout
                #  1) 当timeout==None时，select将一直阻塞，直到监听的文件描述符fd发生变化时返回
                #  2) 当timeout==0时，select不会阻塞，无论文件描述符fd是否有变化，都立刻返回
                #  3) 当timeout>0时，若文件描述符fd无变化，select将被阻塞timeout秒再返回
                rlist, wlist, elist = select.select(_rlist, [], [], timeout_select)

                if elist:
                    debug("error","exception break.")
                    break
                
                if not rlist and not wlist and not elist:
                    continue
                
                for tmp_socket in rlist:
                    is_recv = True
                    # 接收数据
                    data = tmp_socket.recv(self.socket_recv_bufsize)
                    if data == b'':
                        is_recv = False
                        continue
                    
                    # socket_client状态为readable, 当前接收的数据来自客户端
                    if tmp_socket is socket_client: 
                        for conn in socket_server_list:
                            conn.send(data) # 将客户端请求数据发往服务端
                            #print("消息来自客户端：%s\n:" %(socket_client))
                            # debug('proxy', 'client -> server')

                    # socket_server状态为readable, 当前接收的数据来自服务端
                    else:
                        for conn in socket_server_list:
                            pass
                            # 可以记录日志
                            #print(f"得到一个服务器响应:{conn}")
                        if tmp_socket is socket_server_list[0]:
                            socket_client.send(data) # 将第一个服务端响应数据发往客户端
                            print("############raw:#############\n","get a response\n%s" %data)

                time.sleep(self.delay) # 适当延迟以降低CPU占用
            except Exception as e:
                debug("error",e)
                break

        socket_client.close()
        for socket_server in socket_server_list:
            socket_server.close()

    def client_socket_accept(self):
        '''
        获取已经与代理端建立连接的客户端套接字，如无则阻塞，直到可以获取一个建立连接套接字
        返回：socket_client 代理端与客户端之间建立的套接字
        '''
        socket_client, client = self.socket_proxy.accept()
        debug("debug",("client_info" ,client))

        if self.tls == True:
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                #context.load_cert_chain(certfile=server_certfile,keyfile=server_keyfile)
                #socket_client = context.wrap_socket(socket_client, server_side=True)
                context.load_verify_locations(self.server_cacertfile)
                context.load_cert_chain(certfile=self.server_certfile,keyfile=self.server_keyfile)
                socket_client = context.wrap_socket(socket_client, server_side=True)
            except FileNotFoundError:
                debug("error","check certfile or keyfile!")
                sys.exit(-1)
            except Exception as e:
                debug("debug_server",e)
        #  
        return socket_client

    def handle_client_request(self, socket_client):
        try:
            self.__proxy(socket_client)
        except:
            pass

    def run(self):
        try:
            import _thread as thread # py3
        except ImportError:
            import thread # py2
        while True:
            try:
                # 多线程处理客户端请求
                thread.start_new_thread(self.handle_client_request, (self.client_socket_accept(),))
            except KeyboardInterrupt:
                break

def make_ca_cert(option, opt_str, value, parser):

    #ovs-pki init #first
    os.system("ovs-pki req+sign ctl controller")
    debug('debug','get "ctl-privkey.pem" and "ctl-cert.pem" success!')
    os.system("ovs-pki req+sign sc switch")
    debug('debug','get "sc-privkey.pem" and "sc-cert.pem" success!')
    sys.exit(0)

def option_parser():
    from optparse import OptionParser
    parser = OptionParser(description='tls agent')
    #parser = argparse.ArgumentParser(description='tls agent')
    parser.add_option('--host', default="0.0.0.0", help='self hostname or IP address , default 0.0.0.0')
    parser.add_option('-p', '--port', type=int, default=443,help='self TCP port number ,default 443')
    parser.add_option('--server_host', default="127.0.0.1", help='proxy server hostname or IP address,defau1t 127.0.0.1')
    parser.add_option('--server_port', type=int, default=6633,help='proxy server TCP port number')
    parser.add_option('-l', '--listen', type=int, default=10, help='tcp max listen number, default 10')
    parser.add_option('-b', '--bufsize', type=int, default=2,help='recv bufsize, default 2k  bytes size')
    parser.add_option('-d', '--delay', type=int, default=1, help='recv delay ,default 1ms')
    parser.add_option('-T', '--tls', action='store_false',default=True,help='tls enable ,defalut True')
    parser.add_option('-m','--make_ca_cert', action="callback", callback=make_ca_cert, help='test: use gen keyfile and certfile,defalut None')
    # tls client use
    parser.add_option('--client_key', dest='client_keyfile',metavar='KEYFILE', default='/etc/openvswitch/sc-privkey.pem',
                        help='run as server: path to server KEY file ,default in /etc/openvswitch/sc-privkey.pem')
    parser.add_option('--client_cert', dest='client_certfile',metavar='CERTFILE', default='/etc/openvswitch/sc-cert.pem',
                        help='run as server: path to server CERT file ,default  in /etc/openvswitch/sc-cert.pem')
    # tls server use                        
    parser.add_option('--server_key', dest='server_keyfile',metavar='KEYFILE', default='/home/path/to/cert/ctl-privkey.pem',
                        help='run as server: path to server KEY file ,default in /home/path/to/cert/ctl-privkey.pem')
    parser.add_option('--server_cert', dest='server_certfile',metavar='CERTFILE', default='/home/path/to/cert/ctl-cert.pem',
                        help='run as server: path to server CERT file ,default  in /home/path/to/cert/ctl-cert.pem')
    parser.add_option('--server_cacert', dest='server_cacertfile',metavar='CACERTFILE', default='/var/lib/openvswitch/pki/switchca/cacert.pem',
                        help='run as server: path to server CACERT file ,default  in /var/lib/openvswitch/pki/switchca/cacert.pem')


    options, args = parser.parse_args()

    return options, args


def handle_options_server_host(data):
    if "," in data:
        r_list = data.split(',')
        return r_list
    r_list = [data]
    return r_list

def main():
    options, args = option_parser()
    host, port, listen, bufsize, delay ,tls,server_host,server_port,server_key,server_cert, server_cacert, client_cert, client_key = \
        options.host, options.port, options.listen, options.bufsize, options.delay, options.tls,options.server_host,options.server_port,options.server_keyfile,\
        options.server_certfile, options.server_cacertfile,options.client_certfile,options.client_keyfile
    server_host = handle_options_server_host(server_host)
    debug('info', 'bind=%s:%s' % (host, port))
    debug('info', 'listen=%s' % listen)
    debug('info', 'bufsize=%skb, delay=%sms' % (bufsize, delay))
    debug('info', 'tls=%s' % tls)
    debug('info', 'server_host=%s' % server_host)
    debug('info', 'server_port=%s' % server_port)
    if tls:
        debug('info', 'server_key=%s' % server_key)
        debug('info', 'server_cert=%s' % server_cert)
        debug('info', 'server_cacert=%s' % server_cacert)
        debug('info', 'client_key=%s' % client_key)
        debug('info', 'client_cert=%s' % client_cert)
    # 启动tls代理
    tls_proxy = TlsProxyThread(host, port, listen, bufsize, delay,server_host,server_port,tls,server_key,server_cert,server_cacert,client_key,client_cert)
    tls_proxy.start()
    print("test second thread...")
    
if __name__ == '__main__':
    main()



