CC = gcc
CFLAGS = -g -Wall
LDFLAGS =
OBJFILES = ./crypto/aes.o ./crypto/sha256.o cstore.o
TARGET = cstore

all: $(TARGET)

$(TARGET): $(OBJFILES)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJFILES) $(LDFLAGS)

clean:
	rm -f $(OBJFILES) $(TARGET) *.tar *~

test:
	make clean
	make
	./cstore add -p test newarchive.tar alice.txt bob.txt
	./cstore extract -p test newarchive.tar alice.txt