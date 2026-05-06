CC = gcc
COMMIT_SHA := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
CFLAGS = -O2 -Wall -Wextra -std=c99 -static -pthread -I/usr/local/include -DCOMMIT_SHA=\"$(COMMIT_SHA)\"
LIBS = -lsodium -lz -lutil

BUILD_DIR = build

all: $(BUILD_DIR)/dnssh $(BUILD_DIR)/dnssh-server

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/dnssh: dnssh.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ dnssh.c $(LIBS) -DCLIENT_ONLY

$(BUILD_DIR)/dnssh-server: dnssh.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ dnssh.c $(LIBS) -DSERVER_ONLY

clean:
	rm -rf $(BUILD_DIR) dnssh dnssh-server