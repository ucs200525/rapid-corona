# Makefile for eBPF XDP programs
#
# Two modes of operation:
# 1. BCC Runtime: Python uses xdp_filter.c (compiled at runtime by BCC)
# 2. Standalone libbpf: Use this Makefile to compile xdp_filter_libbpf.c
#
# For BCC runtime (Python traffic_monitor.py), no compilation is needed.
# For standalone libbpf loading, run: make

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

# Source and object files (libbpf version for standalone compilation)
LIBBPF_SRC := xdp_filter_libbpf.c
LIBBPF_OBJ := xdp_filter.o

.PHONY: all clean verify help

all: $(LIBBPF_OBJ)

$(LIBBPF_OBJ): $(LIBBPF_SRC) xdp_maps.h
	$(CLANG) $(CFLAGS) -c $< -o $@
	@echo "✓ Compiled $< -> $@"
	@echo ""
	@echo "To load this XDP program:"
	@echo "  sudo ip link set dev <interface> xdp obj $@ sec xdp"

verify: $(LIBBPF_OBJ)
	@echo "Verifying eBPF program..."
	@llvm-objdump -S $(LIBBPF_OBJ) | head -20
	@echo "✓ eBPF program compiled successfully"

clean:
	rm -f *.o
	@echo "✓ Cleaned build artifacts"

help:
	@echo "eBPF XDP Filter Makefile"
	@echo ""
	@echo "This project supports two modes:"
	@echo ""
	@echo "1. BCC Runtime (Python):"
	@echo "   - Uses: xdp_filter.c"
	@echo "   - Compiled at runtime by BCC"
	@echo "   - Run: python -m main"
	@echo ""
	@echo "2. Standalone libbpf:"
	@echo "   - Uses: xdp_filter_libbpf.c"
	@echo "   - Pre-compiled with this Makefile"
	@echo "   - Output: xdp_filter.o"
	@echo ""
	@echo "Targets:"
	@echo "  all     - Compile XDP program (libbpf version)"
	@echo "  verify  - Compile and verify the program"
	@echo "  clean   - Remove build artifacts"
	@echo "  help    - Show this help message"
	@echo ""
	@echo "Output: xdp_filter.o (BPF bytecode)"
