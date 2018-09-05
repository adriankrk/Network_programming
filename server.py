import socket
import sys
import traceback
from threading import Thread
import subprocess
import os
from sctp import *
from daemonize import Daemonize
import logging
import logging.handlers

# -----------------------> SYSLOG <---------------------
logger = logging.getLogger('syslog')
logger.setLevel(logging.DEBUG)

handler = logging.handlers.SysLogHandler('/dev/log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(module)s.%(funcName)s:%(lineno)d %(message)s')

handler.formatter = formatter
logger.addHandler(handler)

# -----------------------> Server <---------------------
class Server:
    ip_addr = '127.0.0.1'
    port = 8888

server = Server()

def main():
    start_server()

def start_server():
    #sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM, proto=socket.IPPROTO_SCTP)

    sock = sctpsocket_tcp(socket.AF_INET)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  #socket.setsockopt(level, optname, value)
    logger.debug("Socket created")

    try:
        sock.bind((server.ip_addr, server.port))
    except:
        logger.error("Bind failed. Error : " + str(sys.exc_info()))
        sys.exit()

    sock.listen(5)
    logger.debug("Socket listening for incoming connections on " + server.ip_addr + ":" + str(server.port))

    while True:
        client, address = sock.accept()
        ip, port = str(address[0]), str(address[1])
        logger.debug("Connected with client " + ip + ":" + port)

        try:
            Thread(target=client_th, args=(client, ip, port)).start()
        except:
            logger.error("Thread did not start.")
            sock.close()


def client_th(client, ip, port, max_buffer_size=1024):
    active = True

    while active:
        try:
            input_from_client = receive_data((client, ip, port), max_buffer_size)

            if "QUIT" in input_from_client:
                logger.debug("Client is requesting to quit")
                client.close()
                logger.debug("Connection " + ip + ":" + port + " closed")
                active = False
            else:
                #logger.debug("Processed result: {}".format(input_from_client))
                if len(input_from_client) == 0:
                    client.sendall("ok".encode("utf8"))
                else:
                    client.sendall(input_from_client.encode("utf8"))
        #except ConnectionResetError:
        except:
            logger.error("Connection was forcibly closed by the remote host " + ip + ":" + port)
            active = False


def receive_data((client, ip, port), max_buffer_size):
    client_input = client.recv(max_buffer_size)
    client_input_size = sys.getsizeof(client_input)

    if client_input_size > max_buffer_size:
        logger.debug("The input size is greater than expected {}".format(client_input_size))

    decoded_cmd = client_input.decode("utf8")

    if "quit" in decoded_cmd:
        return "QUIT"
    else:
        logger.debug("Processing command [" + decoded_cmd+ "] received from client: " + ip + ":" + port)
        result = process_command(decoded_cmd)
        return result


def process_command(client_cmd):
    tab = client_cmd.split(' ')
    if ("cd" in client_cmd) and (len(tab) == 2) and (tab[1] != ''):
        if os.path.isdir(tab[1]):
            os.chdir(tab[1])
            return os.popen("pwd").read()
        else:
            return "Error. Path [" + str(tab[1]) + "] does not exist"
    else:
        returned_output = os.popen(client_cmd).read()
        return returned_output

# ------------------------> DNS <-----------------------------
def get_addr(hostname, port):
    try:
        return socket.getaddrinfo(hostname, port)[0][4]
    except:
        logger.error('Resolving {1}:{2:d} failed'.format(hostname, port))


if __name__ == "__main__":
    try:
        server_host = str(sys.argv[1])
        server.port = int(sys.argv[2])
        server_ip = server_host.split(".")

        daemon_name = os.path.basename(sys.argv[0])
        pidfile = '/tmp/%s' % daemon_name

        if len(server_ip) == 4:
            server.ip_addr = server_host
        else:
            (server.ip_addr, server.port) = get_addr(server_host, server.port)

        daemon = Daemonize(app=daemon_name, pid=pidfile, action=main)
        daemon.start()

    except IndexError:
        print "Server port and hostname or IP is required"