all: clean client server

clean:
	rm client
	rm server

client: client.cpp
	g++ -Wall -o client main_client.cpp -lcrypto

server: server.cpp
	g++ -Wall -o server main_server.cpp -lcrypto
