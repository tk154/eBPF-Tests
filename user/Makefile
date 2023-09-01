include common/OpenWrt.mk

LDLIBS := -lbpf -lelf -lz

SRC_DIR := .
OUT_DIR := output

SRC_FILES := $(wildcard $(SRC_DIR)/*.c)
BIN_FILES := $(patsubst $(SRC_DIR)/%.c,$(OUT_DIR)/%,$(SRC_FILES))

all: $(BIN_FILES)

$(OUT_DIR)/%: $(SRC_DIR)/%.c | $(OUT_DIR)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS) $(LDLIBS)

$(OUT_DIR):
	@mkdir $(OUT_DIR)

clean:
	@rm -rf $(OUT_DIR)
