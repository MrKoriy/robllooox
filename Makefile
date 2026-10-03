CC       ?= clang
CXX      ?= clang++
CFLAGS   := -Wall -Wextra -O2 -fPIC
CXXFLAGS := -Wall -Wextra -O2 -fPIC -std=c++17
LDFLAGS  := -dynamiclib -undefined dynamic_lookup -lc++
TARGET   := payload.dylib

# Universal binary by default; override with: make ARCHS="-arch arm64"
ARCHS    ?= -arch arm64 -arch x86_64

UID_VAL  := $(shell id -u)
SOCKET   := /tmp/inj_ipc_$(UID_VAL).sock

all: $(TARGET)

payload_c.o: payload.c
	$(CC) $(CFLAGS) $(ARCHS) -c payload.c -o payload_c.o

executor_core.o: executor_core.cpp
	$(CXX) $(CXXFLAGS) $(ARCHS) -c executor_core.cpp -o executor_core.o

$(TARGET): payload_c.o executor_core.o
	$(CXX) $(ARCHS) $(LDFLAGS) -o $(TARGET) payload_c.o executor_core.o
	codesign -s - --force $(TARGET)
	@echo "[+] Build and codesign complete: $(TARGET)"

# Build + verify with a quick smoke test
test: $(TARGET)
	@python3 tools/smoke_test.py

# Offline verification of the runtime symbol resolver against the installed
# client: runs the exact resolver code the dylib uses, in link-time address
# space, and prints every resolved address plus its drift vs the old
# constants. Fails when a required symbol stops resolving after an update.
resolvetest: tools/resolver_selftest.cpp luau_resolver.h
	$(CXX) -std=c++17 -O2 -Wall -Wextra -o resolver_selftest tools/resolver_selftest.cpp
	./resolver_selftest

clean:
	rm -f $(TARGET) *.o resolver_selftest

.PHONY: all test resolvetest clean


