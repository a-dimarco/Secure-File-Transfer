all: clean client server

clean:
	rm client
	rm server

client: client.cpp
	g++ -Wall -o client client.cpp

server: server.cpp
	g++ -Wall -o server server.cpp
