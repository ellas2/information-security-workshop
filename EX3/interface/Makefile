CC = gcc
OBJS = main.o aux.o
EXEC = main
COMP_FLAG = -std=c99

$(EXEC) : $(OBJS)
	$(CC) $(OBJS) -o $@
main.o: main.c aux.h
	$(CC) $(COMP_FLAG) -c $*.c
aux.o: aux.c aux.h
	$(CC) $(COMP_FLAG) -c $*.c
clean:
	rm -f $(OBJS) $(EXEC)
