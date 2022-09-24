CC = clang
TARGET = locker
LDFLAGS = -lcrypto -lssl

all:
	@$(CC) -o $(TARGET) locker.c $(LDFLAGS)

clean:
	@rm $(TARGET)