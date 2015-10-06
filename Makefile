#
# Makefile for Webfuzzer (c) gunzip
#

CFLAGS=-g -O3 -Wall -DCOLORS
CC=gcc
LIBS=-lsocket -lnsl -lresolv
MOBJS=util.o getpost.o header.o parseform.o hash.o network.o parselinks.o cookies.o webfuzzer.o

#CFLAGS += -DDEBUG
#LIBS += -lresolv

default:	webfuzzer

webfuzzer:	main.c $(MOBJS)
		$(CC) $(CFLAGS) -o webfuzzer main.c $(MOBJS)

sunos:	main.c $(MOBJS)
	$(CC) $(CFLAGS) -o webfuzzer main.c $(MOBJS) $(LIBS)

clean:
	rm -rf *.o webfuzzer core

