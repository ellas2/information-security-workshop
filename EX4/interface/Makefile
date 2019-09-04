CC = gcc
OBJS = main.o auxil.o 
EXEC = main
COMP_FLAG = -std=c99

$(EXEC) : $(OBJS)
	$(CC) $(OBJS) -o $@
main.o: main.c auxil.h 
	$(CC) $(COMP_FLAG) -c $*.c
auxil.o: auxil.c auxil.h
	$(CC) $(COMP_FLAG) -c $*.c
clean:
	rm -f $(OBJS) $(EXEC)
