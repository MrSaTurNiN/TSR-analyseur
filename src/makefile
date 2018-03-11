CC = gcc
CFLAGS = -O2 -Wall
LDFLAGS = -lpcap
EXEC = analyseur
SRC =  application.c capture.c transport.c reseau.c liaison.c
OBJ = $(SRC:.c=.o)

all: $(OBJ)
	$(CC) -o $(EXEC) $^ $(LDFLAGS) -g
	mv $(EXEC) ../$(EXEC)

%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS) -g

clean:
	/bin/rm *.o
