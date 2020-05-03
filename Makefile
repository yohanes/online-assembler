PREFIX=/usr/local/wasm

.PHONY: all

all: casm.wasm cdisasm.wasm casmdisasm.wasm

casm.wasm: asm.cpp
	em++ -s "EXPORTED_FUNCTIONS=['_assemble']" -s EXTRA_EXPORTED_RUNTIME_METHODS='["ccall", "cwrap"]'  asm.cpp -I$(PREFIX)/include/ -L$(PREFIX)/lib -lkeystone -o casm.js
cdisasm.wasm: disasm.cpp
	em++ -s "EXPORTED_FUNCTIONS=['_disassemble']" -s EXTRA_EXPORTED_RUNTIME_METHODS='["ccall", "cwrap"]'  disasm.cpp -I$(PREFIX)/include/ -L$(PREFIX)/lib -lcapstone -o cdisasm.js

casmdisasm.wasm: asm.cpp disasm.cpp
	em++ -s "EXPORTED_FUNCTIONS=['_disassemble', '_assemble']" -s EXTRA_EXPORTED_RUNTIME_METHODS='["ccall", "cwrap"]'  asm.cpp disasm.cpp -I$(PREFIX)/include/ -L$(PREFIX)/lib -lcapstone -lkeystone -o casmdisasm.js
