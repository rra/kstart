# For solaris
CFLAGS= -g -I/usr/leland/include -DDO_AKLOG -D__srv4__ -DUSE_UNISTD_H 
CC=gcc 
LDFLAGS= -L/usr/leland/lib
# For solaris
LIBS= -lsocket -lnsl -lkrb -ldes
# For others
#LIBS= -lkrb -ldes

# Cheesy makefile to build ksrvtgt 

kstart: kstart.o 
	$(CC) $(LDFLAGS)  -o kstart kstart.o $(LIBS)

install: kstart
	mv ./kstart ../bin/kstart

