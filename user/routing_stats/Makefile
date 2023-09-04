ifdef OPENWRT_DIR
include ../common/OpenWrt.mk
endif

LDLIBS := -lbpf -lelf -lz

OUT_DIR := output
TARGET := $(OUT_DIR)/routing_stats

$(TARGET): main.c | $(OUT_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(LDLIBS)

$(OUT_DIR):
	@mkdir $(OUT_DIR)

clean:
	@rm -rf $(OUT_DIR)
