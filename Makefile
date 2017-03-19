CC = gcc
AR = ar rcs
CFLAGS = -O2 -Wall -Wextra -std=gnu99

TARGET = libsec.a
SRCS = libsec.c

OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(AR) $@ $^

%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	rm -f $(TARGET)
	rm -f $(OBJS)
