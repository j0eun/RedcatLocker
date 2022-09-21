CC = clang
SRC = ./src
BIN = ./bin
TARGET = locker
LDFLAGS = -lcrypto -lssl

all:
	@$(CC) -o $(BIN)/$(TARGET) $(SRC)/locker.c $(LDFLAGS)

clean:
	@rm $(BIN)/*