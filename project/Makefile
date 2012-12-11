#/**
# * Course: CS 165 Fall 2012
# * Username:marshb/bmars003
# * Email address: bmars003@ucr.edu 
# *
# * Assignment: Project
# * Filename : Makefile
# *
# * We hereby certify that the contents of this file represent
# * our team's original work. Any outside code has been approved
# * for use by the instructor or TA. In such cases an explicit
# * reference to the source of said code is included.
# */
COMPILER	= g++ -g
FLAGS	 	= 
LIBRARIES	= -l ssl -l crypto
#CXXFLAGS=-g -W -Wall -Werror -ansi -pedantic

all: Server/ssl_server.cpp Client/ssl_client.cpp
	$(COMPILER) $(FLAGS) -o Server/server ./Server/ssl_server.cpp $(LIBRARIES)
	$(COMPILER) $(FLAGS) -o Client/client ./Client/ssl_client.cpp $(LIBRARIES)
clean:
	rm -rf *.o a.out *~ *# Server/server Client/client Client/*.txt Server/*.o Server/*~ Server/*# Server/*.dSYM Client/*.o Client/*~ Client/*# Client/*.dSYM
