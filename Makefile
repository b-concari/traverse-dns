CC=gcc
CC_OPTS=-std=c99

CC_LIBS=-pthread
CC_OUT=traverse

SOURCES := $(wildcard *.c)

.PHONY: clean

all: $(SOURCES)
	$(CC) $(CC_OPTS) -o $(CC_OUT) $(SOURCES) $(CC_LIBS)

clean:
	rm $(CC_OUT)
