all: client server
#-Werror -Wformat-security
client: Client/main_client.cpp
	g++ -Wall -Wextra -Wpedantic -Wstack-protector -Wshadow -fstack-protector-strong -fPIE -o client_app Client/main_client.cpp Client/client.cpp Utils/Socket/connection_manager.cpp Utils/Crypto/crypto.cpp Utils/Util/util.cpp -lcrypto

server: Server/main_server.cpp
	g++ -Wall -Wextra -Wpedantic -Wstack-protector -Wshadow -fstack-protector-strong -fPIE -o server_app Server/main_server.cpp Server/server.cpp Utils/Socket/connection_manager.cpp Utils/Crypto/crypto.cpp Utils/Util/util.cpp -lcrypto
