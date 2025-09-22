CC = gcc
CFLAGS = -Wall -Wextra -O2

SRC = src/filesys.c
TARGET = filesys

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET) fat32.img

.PHONY: all clean run
