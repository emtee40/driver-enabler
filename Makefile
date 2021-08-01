CC := x86_64-w64-mingw32-clang
LDFLAGS += -shared
CFLAGS += -O3

all: shim.dll

shim.dll: shim.c exports.def
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	$(RM) shim.dll

.PHONY: all clean
