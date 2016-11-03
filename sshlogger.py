#!/usr/bin/env python2.7

import sys
import socket
import select
import thread
import threading

import paramiko

VERSION = '1.0'

from optparse import OptionParser
from optparse import OptionGroup

parser = OptionParser(usage='%prog [options]\nVersion: ' + VERSION)

parser.add_option('-l', '--port', help='local port to bind to', nargs = 1, default=2222, type='int')
parser.add_option('-k', '--key', help='ssh server key', nargs = 1, default='server.key')
parser.add_option('-i', '--ip', help='filename to log ips', nargs = 1, default='ips.txt')
parser.add_option('-p', '--password', help='filename to log credentials', nargs = 1, default='passwords.txt')

#generate keys with 'ssh-keygen -t rsa -f server.key'
HOST_KEY = paramiko.RSAKey(filename='server.key')
PASSWORD_FILE = 'passwords.txt'
IP_FILE = 'ips.txt'

LOGFILE_LOCK = threading.Lock()
SOCKET_TIMEOUT = 2

def file_log(file_path, msg):
    LOGFILE_LOCK.acquire()
    try:
        with open(file_path, 'a') as fd:
            fd.write(msg + '\n')
    finally:
        LOGFILE_LOCK.release()

def log_ip(peername):
    print "[+] New connecion from %s:%s" % peername
    file_log(IP_FILE, peername[0])

def log_credentials(username, password):
    print "[+] New login: %s %s" %(username, password)
    file_log(PASSWORD_FILE, username + " " + password)

class SSHServerHandler(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def check_auth_password(self, username, password):
        log_credentials(username, password)
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return 'password'


def handleConnection(client):
    log_ip(client.getpeername())

    transport = paramiko.Transport(client)
    transport.add_server_key(HOST_KEY)

    server_handler = SSHServerHandler()

    transport.start_server(server=server_handler)

    channel = transport.accept(1)
    if not channel is None:
        channel.close()


def create_bind_socket(port):
    print "[+] Creating server on port %s" % port

    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('', port))
        server_socket.listen(100)

        return server_socket
    except Exception as e:
        print "[-] Failed to create socket"
        print e

    return None


def serve_forever(server_socket):
    print "[+] Waiting for new SSH connexion"

    serve = True
    while serve:
        try:
            readable, writable, errored = select.select([server_socket], [], [], SOCKET_TIMEOUT)

            for s in readable:
                if s is server_socket:
                    client_socket, client_addr = server_socket.accept()
                    thread.start_new_thread(handleConnection, (client_socket,))
        except KeyboardInterrupt:
            print "[-] <Ctrl-C> stopping server..."
            serve = False
        except Exception as e:
            print "[-] Client handling"
            print e
            serve = False

    server_socket.close()


def main(options, arguments):
    HOST_KEY = paramiko.RSAKey(filename=options.key)
    PASSWORD_FILE = options.password
    IP_FIE = options.ip

    port = int(options.port)
    server_socket = create_bind_socket(port)

    if not server_socket:
        sys.exit(1)

    paramiko.util.log_to_file('paramiko.log')

    serve_forever(server_socket)


if __name__ == "__main__":
    options, arguments = parser.parse_args()
    main(options, arguments)
