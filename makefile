CC = clang
CFLAGS = -Wall -Wextra -O3 -I./src -ftrapv -save-temps=obj

.PHONY: all
all: bin/factorial bin/fibonacci bin/unittest

bin/factorial: bin/bignum.o bin/factorial.o
	${CC} $(LDFLAGS) -o $@ $^

bin/fibonacci: bin/bignum.o bin/fibonacci.o
	${CC} $(LDFLAGS) -o $@ $^

bin/unittest: bin/bignum.o bin/unittest.o
	${CC} $(LDFLAGS) -o $@ $^

bin/%.o: src/%.c
	${CC} ${CFLAGS} -c $< -o $@

bin/%.o: test/%.c
	${CC} ${CFLAGS} -c $< -o $@

.PHONY: clean
clean:
	rm -f ./bin/*

.PHONY: docs
docs:
	doxygen ./docs/Doxyfile
