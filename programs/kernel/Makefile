CLANG := clang
CFLAGS := -O2 -g -Wall -target bpf

SRC_DIR := .
OBJ_DIR := obj

SRC_FILES := $(wildcard $(SRC_DIR)/*.c)

XDP_LE_OBJ_FILES := $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/xdp_le_%.o, $(SRC_FILES))
TC_LE_OBJ_FILES  := $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/tc_le_%.o,  $(SRC_FILES))
XDP_BE_OBJ_FILES := $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/xdp_be_%.o, $(SRC_FILES))
TC_BE_OBJ_FILES  := $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/tc_be_%.o,  $(SRC_FILES))

XDP_ARGS := -DXDP_PROGRAM
TC_ARGS  := -DTC_PROGRAM

all: xdp-le tc-le xdp-be tc-be

xdp: xdp-le xdp-be

tc: tc-le tc-be

le: xdp-le tc-le

be: xdp-be tc-be

xdp-le: $(XDP_LE_OBJ_FILES)

tc-le: $(TC_LE_OBJ_FILES)

xdp-be: $(XDP_BE_OBJ_FILES)

tc-be: $(TC_BE_OBJ_FILES)

clean:
	@rm -rf $(OBJ_DIR)

$(OBJ_DIR)/xdp_le_%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CLANG) $(CFLAGS) -mlittle-endian $(XDP_ARGS) -c $< -o $@

$(OBJ_DIR)/tc_le_%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CLANG) $(CFLAGS) -mlittle-endian $(TC_ARGS) -c $< -o $@

$(OBJ_DIR)/xdp_be_%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CLANG) $(CFLAGS) -mbig-endian $(XDP_ARGS) -c $< -o $@

$(OBJ_DIR)/tc_be_%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CLANG) $(CFLAGS) -mbig-endian $(TC_ARGS) -c $< -o $@

$(OBJ_DIR):
	@mkdir -p $(OBJ_DIR)
