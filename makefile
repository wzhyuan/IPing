PROGRAM = delay
EXECNAME = __EXECNAME__="\"$(PROGRAM)\""
VERSION_ID = 1.0.0.0

CC = g++


CFLAGS =  -g -Wall -Werror   

LIBS = -lnfnetlink -lnetfilter_queue  -lpthread -lnetfilter_conntrack
OBJS = delay.o

all: delay
delay.o:
	$(CC) -c delay.cpp 
delay: $(OBJS)
	$(CC) -o delay $(OBJS) $(LIBS)
	
clean:
	rm -f   *.o delay

