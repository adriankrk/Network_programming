import socket
import sys
from sctp import *


def main((server_ip, server_port)):

    sock = sctpsocket_tcp(socket.AF_INET)

    try:
        sock.connect((server_ip, server_port))
    except:
        print "Error when trying connect to server " + server_ip + ":" + str(server_port)
        sys.exit()

    print("Write 'quit' to exit")
    command = raw_input(">")

    while command != 'quit':
        if (command != ""):
            sock.sctp_send(command.encode("utf8"))
            answer = recvall(sock).decode("utf8")
            print(answer)
        command = raw_input(">")

    sock.send('quit'.encode("utf8"))

def recvall(sock):
    BUFF_SIZE = 4096
    data = b''
    while True:
        part = sock.recv(BUFF_SIZE)
        data += part
        if len(part) < BUFF_SIZE:
            break
    return data

# ------------------------> DNS <--------------------------
def get_addr(hostname, port):
    try:
        return socket.getaddrinfo(hostname, port)[0][4]
    except:
        print 'Resolving {1}:{2:d} Failed'.format(hostname, port)

if __name__ == "__main__":
    try:
        server_host = str(sys.argv[1])
        server_port = int(sys.argv[2])
        server_tab = server_host.split(".")

        if len(server_tab) == 4:
            main((server_host, server_port))
        else:
            main(get_addr(server_host, server_port))

    except IndexError:
        print "Server port and hostname or IP is required"

