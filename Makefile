CC=gcc
CFLAGS= -g
LFLAGS=

SOURCES  := $(wildcard *.c)
INCLUDES := $(wildcard *.h)
OBJECTS  := $(SOURCES:%.c=%.o)

LISTENER_SOURCES := listener.c
SENDER_SOURCES   := traceroute.c
COMMON_SOURCES   := dbg-util.c util.c

LISTENER_OBJECTS := $(LISTENER_SOURCES:.c=.o)
SENDER_OBJECTS   := $(SENDER_SOURCES:.c=.o)
COMMON_OBJECTS   := $(COMMON_SOURCES:.c=.o)

rm       = rm -f


$(info $$COMMON_SOURCES [$(COMMON_SOURCES)])
$(info $$SENDER_SOURCES [$(SENDER_SOURCES)])
$(info $$LISTENER_SOURCES [$(LISTENER_SOURCES)])

$(info $$COMMON_OBJECTS [$(COMMON_OBJECTS)])
$(info $$SENDER_OBJECTS [$(SENDER_OBJECTS)])
$(info $$LISTENER_OBJECTS [$(LISTENER_OBJECTS)])

all: listener sender	

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

listener: $(LISTENER_OBJECTS) $(COMMON_OBJECTS)
	$(CC) $(LISTENER_OBJECTS) $(COMMON_OBJECTS) $(LFLAGS) -o $@

sender: $(SENDER_OBJECTS) $(COMMON_OBJECTS)
	$(CC) $(SENDER_OBJECTS) $(COMMON_OBJECTS) $(LFLAGS) -o $@

.PHONY: clean
clean:
	$(rm) $(OBJECTS)
	@echo "Object file cleanup complete!"

.PHONY: remove
distclean: clean
	$(rm) listener sender
	@echo "Executable removed!"
