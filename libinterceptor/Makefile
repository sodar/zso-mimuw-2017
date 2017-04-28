TARGETS = \
	libintercept.so \
	$(null)

LIBINTERCEPTOR_OBJECTS = \
	interceptor.o \
	$(null)

CC=gcc

CFLAGS  = -Wall -Werror -fPIC
#CFLAGS += -g -DDEBUG=1

all: libinterceptor.so

libinterceptor.so: $(LIBINTERCEPTOR_OBJECTS)
	$(CC) -shared -fPIC -Wl,-soname,$@ -o $@ $^ -lc

#
# Object files
#

%.o: %.c
	$(CC) -c $(CFLAGS) -I./ -o $@ $<

.PHONY: clean
clean:
	rm -f *.o
	rm -f *.so
	rm -f $(TARGETS)
