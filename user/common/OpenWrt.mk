CC := $(OPENWRT_DIR)/staging_dir/toolchain-x86_64_gcc-12.3.0_musl/bin/x86_64-openwrt-linux-musl-gcc-12.3.0
CFLAGS := -I$(OPENWRT_DIR)/staging_dir/target-x86_64_musl/usr/include
LDFLAGS := -L$(OPENWRT_DIR)/staging_dir/target-x86_64_musl/usr/lib

STAGING_DIR = $(OPENWRT_DIR)/staging_dir/toolchain-x86_64_gcc-12.3.0_musl:$(OPENWRT_DIR)/staging_dir/target-x86_64_musl/usr
export STAGING_DIR
