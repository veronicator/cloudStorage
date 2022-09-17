CFLAGS = -Wall -lcrypto -lpthread

all: client server

client: client.o client_main.o security_util.o
	g++ ${CFLAGS} client.o client_main.o security_util.o -o client.exe

server: server.o server_main.o security_util.o
	g++ ${CFLAGS} server.o server_main.o security_util.o -o server.exe

client.o: client/client.cpp client/client.h util/security_util.h util/symbols.h
	g++ -c client/client.cpp

client_main.o: client/client_main.cpp client/client.h util/security_util.h  util/symbols.h
	g++ -c client/client_main.cpp

security_util.o: util/security_util.cpp util/security_util.h util/symbols.h
	g++ -c util/security_util.cpp

server.o: server/server.cpp server/server.h util/security_util.h util/symbols.h
	g++ -c server/server.cpp

server_main.o: server/server_main.cpp server/server.h util/security_util.h util/symbols.h
	g++ -c server/server_main.cpp

clean: rm *.o client server