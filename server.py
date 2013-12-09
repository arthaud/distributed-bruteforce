#!/usr/bin/env python3
# -*- coding: utf8 -*-
import socket
import select
from struct import pack

def password_by_index(index, charset):
    s = ''
    while index >= 0:
        s += charset[index % len(charset)]
        index = index // len(charset) - 1

    return s

def server(charset, packet_size, bind_address, port):
    ''' Launch a distributed bruteforce server '''

    # server socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.setblocking(False)
    server.bind((bind_address, port))
    server.listen(5)

    clients = []
    addresses = {}
    current_packet = 0
    exit = False

    # begin message
    print('Server listening on %s:%s' % (bind_address, port))
    print('charset: %s' % charset)
    print('packet size: %s' % packet_size)
    print()

    # main loop
    while not exit:
        readable, writable, exceptional = select.select(clients + [server], [], [server])

        for s in readable:
            if s is server: # incoming connection
                client, (ip, port) = server.accept()
                client.setblocking(False)
                clients.append(client)
                addresses[client] = '%s:%s' % (ip, port)
                print('client %s:%s joined' % (ip, port))

                # send charset
                client.sendall(charset.encode('latin').ljust(256, b'\0'))

                # send packet_size
                client.sendall(pack('<I', packet_size))

                # send work
                client.sendall(pack('<Q', current_packet)) # from current_packet to current_packet + packet_size - 1
                current_packet += packet_size
            else:
                data = s.recv(1024)
                if data: # end of a work
                    for byte in data:
                        if byte == 0:
                            # send work
                            print('done: %s passwords - current: %s' % (current_packet, password_by_index(current_packet, charset)))
                            s.sendall(pack('<Q', current_packet))
                            current_packet += packet_size
                        else:
                            print('passphrase found on %s !' % addresses[s])
                            exit = True
                else:
                    print('client disconnected')
                    clients.remove(s)
                    s.close()

        if exceptional:
            exit = True

    print('exiting...')
    for client in clients:
        client.close()

    server.close()

if __name__ == '__main__':
    import argparse

    # letters
    default_charset = ''.join(map(chr, range(97, 123)))
    default_charset += default_charset.upper()
    default_charset += ' '

    # numbers
    default_charset += ''.join(map(str, range(0, 10)))

    # special characters
    default_charset += ''.join(map(chr, range(ord('!'), ord('/')+1)))
    default_charset += ''.join(map(chr, range(ord(':'), ord('@')+1)))
    default_charset += ''.join(map(chr, range(ord('{'), ord('~')+1)))
    default_charset += ''.join(map(chr, range(ord('['), ord('_')+1)))

    parser = argparse.ArgumentParser(description='Server for distributed bruteforce')
    parser.add_argument('-c', '--charset', default=default_charset,
        help='The charset to use for bruteforce')
    parser.add_argument('-p', '--packet_size', default=500000,
        help='The number of passwords to try by packet')
    parser.add_argument('-b', '--bind_address', default='0.0.0.0',
        help='Use bind_address on the local machine as the source address of the connection. default is 0.0.0.0 (all available interfaces)')
    parser.add_argument('port', type=int,
        help='The port on which the server listens for connections')

    args = parser.parse_args()
    server(args.charset, args.packet_size, args.bind_address, args.port)
