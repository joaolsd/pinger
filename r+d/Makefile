CC=cc -I /opt/homebrew//include
FRAMEWORK=-framework CoreFoundation -framework CoreServices
STATIC_LIBRARIES=/opt/homebrew/lib/libuv.a
#DYLD_LIBRARIES=/usr/local/lib/libuv.dylib

all: interface-static 

interface-static: libuv_iface.c
	$(CC) -o interface-static libuv_iface.c $(FRAMEWORK) $(STATIC_LIBRARIES)