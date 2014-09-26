CFLAGS=-lssl -lcrypto -Wall -O3

all:
	$(CC) $(CFLAGS) ssh-pk-crack.c -o ssh-pk-crack
clean:
	rm -f ssh-pk-crack
