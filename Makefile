PREFIX=/wasm
index.wasm: asm.c
	emcc -s "EXPORTED_FUNCTIONS=['_assemble']" -s EXTRA_EXPORTED_RUNTIME_METHODS='["ccall", "cwrap"]'  asm.c -I$(PREFIX)/include/ -L$(PREFIX)/lib -lkeystone  -o index.js

