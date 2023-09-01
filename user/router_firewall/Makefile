include ../common/OpenWrt.mk

LDLIBS := -lbpf -lelf -lz

OUT_DIR := output
TARGET := $(OUT_DIR)/router_firewall
SOURCES := firewall.c vlan.c

BPF_LOADER_OBJECT := $(OUT_DIR)/bpf_loader.o
BPF_LOADER_SOURCE := ../common/bpf_loader.c

OBJECTS := $(patsubst %.c,$(OUT_DIR)/%.o,$(notdir $(SOURCES))) $(BPF_LOADER_OBJECT)

$(TARGET): main.c $(OBJECTS) | $(OUT_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(LDLIBS)

$(OUT_DIR)/%.o: %.c | $(OUT_DIR)
	$(CC) $(CFLAGS) -c $< -o $@ $(LDFLAGS) $(LDLIBS)

$(BPF_LOADER_OBJECT): $(BPF_LOADER_SOURCE) | $(OUT_DIR)
	$(CC) $(CFLAGS) -c $< -o $@ $(LDFLAGS) $(LDLIBS)

$(OUT_DIR):
	@mkdir $(OUT_DIR)

clean:
	@rm -rf $(OUT_DIR)
