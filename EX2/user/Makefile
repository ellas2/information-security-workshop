all: main.o
	gcc main.c
clean:
	rm -rf *.o main a.out
main.o: main.c
	gcc -std=c99 -Wall -Wextra -Werror -pedantic-errors -c main.c
	
