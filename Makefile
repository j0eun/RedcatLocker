CC = clang
ENCRYPTOR = locker
DECRYPTOR = unlocker
LDFLAGS = -lcrypto -lssl

all:
	@$(CC) -o $(ENCRYPTOR) locker.c $(LDFLAGS)
	@$(CC) -o $(DECRYPTOR) unlocker.c $(LDFLAGS)

clean:
	@rm $(ENCRYPTOR)
	@rm $(DECRYPTOR)