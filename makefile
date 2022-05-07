client: ./Client/client.cpp
	gcc -Wall -o client ./Client/client.cpp

server: ./Server/server.cpp
	gcc -Wall -o server ./Server/server.cpp
