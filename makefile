all: client server

client: Client/main_client.cpp
	g++ -Wall -o client_app Client/main_client.cpp Client/client.cpp Utils/Socket/connection_manager.cpp -lcrypto

server: Server/main_server.cpp
	g++ -Wall -o server_app Server/main_server.cpp Server/server.cpp Utils/Socket/connection_manager.cpp -lcrypto
