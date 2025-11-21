CC = gcc
CFLAGS = -Wall -Wextra

TARGET = CharanchiK-bash

all: $(TARGET)

$(TARGET): CharanchiK-bash.c
	$(CC) $(CFLAGS) CharanchiK-bash.c -o $(TARGET)

clean:
	rm -f $(TARGET)
