# Makefile for eBPF XDP programs

CLANG := clang
LLC := llc
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Kernel headers path
KERNEL_HEADERS := /usr/include

# BPF include path (adjust if needed)
BPF_INCLUDE := /usr/include/bpf

# Compiler flags
CFLAGS := -O2 -g -Wall -Werror \
	-target bpf \
	-D__BPF_TRACING__ \
	-I$(KERNEL_HEADERS) \
	-I$(BPF_INCLUDE) \
	-Wno-unused-value \
	-Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types

# Source and object files
SRC := xdp_filter.c
OBJ := $(SRC:.c=.o)

.PHONY: all clean verify

all: $(OBJ)

%.o: %.c xdp_maps.h
	$(CLANG) $(CFLAGS) -c $< -o $@
	@echo "✓ Compiled $< -> $@"

verify: $(OBJ)
	@echo "Verifying eBPF program..."
	@llvm-objdump -S $(OBJ) | head -20
	@echo "✓ eBPF program compiled successfully"

clean:
	rm -f *.o
	@echo "✓ Cleaned build artifacts"

help:
	@echo "eBPF XDP Filter Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all     - Compile XDP program (default)"
	@echo "  verify  - Compile and verify the program"
	@echo "  clean   - Remove build artifacts"
	@echo "  help    - Show this help message"
	@echo ""
	@echo "Output: xdp_filter.o (BPF bytecode)"
