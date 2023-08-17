CC := ~/Mellanox/openwrt/staging_dir/toolchain-x86_64_gcc-12.3.0_musl/bin/x86_64-openwrt-linux-musl-gcc-12.3.0
LIBS := -lbpf

STAGING_DIR = ~/Mellanox/openwrt/staging_dir/toolchain-x86_64_gcc-12.3.0_musl:~/Mellanox/openwrt/staging_dir/target-x86_64_musl/usr
export STAGING_DIR

SRC_DIR := .
OUT_DIR := output

SRC_FILES := $(wildcard $(SRC_DIR)/*.c)
BIN_FILES := $(patsubst $(SRC_DIR)/%.c,$(OUT_DIR)/%,$(SRC_FILES))

all: $(BIN_FILES)

$(OUT_DIR)/%: $(SRC_DIR)/%.c | $(OUT_DIR)
	$(CC) $< -o $@ $(LIBS)

$(OUT_DIR):
	@mkdir $(OUT_DIR)

clean:
	@rm -rf $(OUT_DIR)
