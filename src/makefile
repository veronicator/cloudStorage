CFLAGS = -Wall -lcrypto -lpthread

all: client server

client: client.o client_main.o security_utils.o
	g++ ${CFLAGS} client.o client_main.o security_utils.o -o client.exe

server: server.o server_main.o security_utils.o
	g++ ${CFLAGS} server.o server_main.o security_utils.o -o server.exe

client.o: client/client.cpp client/client.h utils/security_utils.h utils/symbols.h
	g++ -c client/client.cpp

client_main.o: client/client_main.cpp client/client.h utils/security_utils.h  utils/symbols.h
	g++ -c client/client_main.cpp

security_utils.o: utils/security_utils.cpp utils/security_utils.h utils/symbols.h
	g++ -c utils/security_utils.cpp

server.o: server/server.cpp server/server.h utils/security_utils.h utils/symbols.h
	g++ -c server/server.cpp

server_main.o: server/server_main.cpp server/server.h utils/security_utils.h utils/symbols.h
	g++ -c server/server_main.cpp

clean: rm *.o client server