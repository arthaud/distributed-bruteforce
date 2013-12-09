distributed-bruteforce
======================

A tool for distributing bruteforce.

server
******

The server is a simple python program that distribute work for client.
You can choose a charset (i.e characters used for bruteforce) and the packet size (i.e the number of passwords by work).

see ./server.py --help

client
******

The client is a C program that connect to the server, and receive works.
the client manage a subprocess that read stdin an try each line as a password.
the subprocess should end when the password is found.

compile with: gcc -Wall -O2 -o client client.c
see ./client --help

TODO
====

* Manage big endian processor
