all: clean client server

clean:
	rm client_app
	rm server_app

client:
	g++ -Wall -o client_app Client/main_client.cpp Client/client.cpp Utils/Socket/connection_manager.cpp -lcrypto

server:
	g++ -Wall -o server_app Server/main_server.cpp Server/server.cpp Utils/Socket/connection_manager.cpp -lcrypto
