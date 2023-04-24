# Cloud Storage

University project for the course of **Foundations of Cybersecurity**  @ Univerity of Pisa (MSc *Computer Engineering* and *Artificial Intelligence and Data Engineering*)

## Overview
The aim of this project is to implement a Client-Server application that emulates a simple Cloud Storage, offering confidentiality, integrity, authenticity and reliability.

## Compile and Run the code
In order to compile and run the code, you must be in the *cloudStorage/src/* folder of the project and type:
```sh
make
```
in order to compile the executable for both client and server.

To execute the code, open different terminals for server and clients and type:
* for the server:
```sh
./server.exe
```
* for the client (in another terminal):
```sh
./client.exe <server_ip>
```
for testing on the same machine, use <localhost> as the <server_ip>.

The user_key password is the name of the user itself.
