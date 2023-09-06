CC = gcc
CFLAGS = -Wall -Wextra -Wpedantic -O3 -std=c99 -Wconversion -Wmissing-prototypes -DFILE_NAME=$(FILE_NAME)
LDFLAGS = -lcrypto -lm -lssl
OBJFILES = cycles.o statelesslamport.o benchmark.o
TARGET = benchmark

all: $(TARGET)

$(TARGET): $(OBJFILES)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJFILES) $(LDFLAGS)
clean:
	rm -f $(OBJFILES) $(TARGET) *~
