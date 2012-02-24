all: build

build:
	gcc --std=gnu99 -Wall -Werror -c proof_of_concept.c
	gcc -Wall -Werror -pthread -o proof_of_concept proof_of_concept.o

clean:
	-rm proof_of_concept proof_of_concept.o
