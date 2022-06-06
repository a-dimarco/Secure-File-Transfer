all: client server
#-Werror -Wformat-security -Wall -Wextra -Wpedantic -Wstack-protector -Wshadow -fstack-protector-strong -fPIE
client: Client/main_client.cpp
	g++ -Wall -Wextra -Wformat-security -fPIE -Wstrict-overflow=5 -o client_app Client/main_client.cpp Client/client.cpp Utils/Socket/connection_manager.cpp Utils/Crypto/crypto.cpp Utils/Util/util.cpp -lcrypto

server: Server/main_server.cpp
	g++ -Wall -Wextra -Wformat-security -fPIE -Wstrict-overflow=5 -o server_app Server/main_server.cpp Server/server.cpp Utils/Socket/connection_manager.cpp Utils/Crypto/crypto.cpp Utils/Util/util.cpp -lcrypto
