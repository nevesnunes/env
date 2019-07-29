#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

import socket, sys

HOST = '127.0.0.1'
PORT = 5000

mySocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
mySocket.bind((HOST,PORT))
while 1:
    mySocket.listen(2)
    connection, address = mySocket.accept()

    msgServer="Connected to server."
    connection.send(msgServer.encode("Utf8"))
    while 1:
        msgClient = connection.recv(1024).decode("Utf8")
        if msgClient.upper() == "END" or msgClient == "":
            break
        msgServer = input("S> ")
        connection.send(msgServer.encode("Utf8"))

    connection.send("end".encode("Utf8"))
    connection.close()
