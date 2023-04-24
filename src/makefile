CFLAGS = -Wall -lpthread -lcrypto -lstdc++fs

all: clean server.exe client.exe

server.exe: server.o server_main.o security_utils.o
	g++ server.o server_main.o security_utils.o -o server.exe ${CFLAGS}

client.exe: client.o client_main.o security_utils.o
	g++ client.o client_main.o security_utils.o -o client.exe ${CFLAGS}

security_utils.o: utils/security_utils.h utils/symbols.h
	g++ -c utils/security_utils.cpp utils/symbols.h ${CFLAGS}

server.o: server/server.h utils/security_utils.h utils/symbols.h
	g++ -c server/server.cpp ${CFLAGS}

server_main.o: server/server.h utils/security_utils.h utils/symbols.h
	g++ -c server/server_main.cpp ${CFLAGS}

client.o: client/client.h utils/security_utils.h utils/symbols.h
	g++ -c client/client.cpp ${CFLAGS}

client_main.o: client/client.h utils/security_utils.h  utils/symbols.h
	g++ -c client/client_main.cpp ${CFLAGS}

clean:
	rm -rf *.o *.exe