CFLAGS= -g -I/usr/leland/include -DDO_AKLOG -DBSD42
CC=gcc 
LDFLAGS= -L/usr/leland/lib
LIBS= -lkrb -ldes

# Cheesy makefile to build ksrvtgt 

kstart: kstart.o 
	$(CC) $(LDFLAGS)  -o kstart kstart.o $(LIBS)

install: kstart
	mv ./kstart ../bin/kstart
	
