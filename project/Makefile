COMPILER	= g++
FLAGS	 	= 
LIBRARIES	= -l ssl -l crypto
#CXXFLAGS=-g -W -Wall -Werror -ansi -pedantic

all: Server/ssl_server.cpp Client/ssl_client.cpp
	$(COMPILER) $(FLAGS) -o Server/server ./Server/ssl_server.cpp $(LIBRARIES)
	$(COMPILER) $(FLAGS) -o Client/client ./Client/ssl_client.cpp $(LIBRARIES)
clean:
	rm -rf *.o a.out *~ *#
