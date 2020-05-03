# Online assembler and disassembler

Requires web browser with WASM support. Tested on latest Firefox, Google Chrome, and Safari (both Desktop and Mobile).

Demos are split because on some version of Google Chrome on Windows, the version with both the assembler and disassembler causes the browser to hang.

* [Assembler/Disassembler Live Demo](https://asm.x32.dev/both.html)
* [Assembler only Live Demo](https://asm.x32.dev)
* [Disassembler only Live Demo](https://disasm.x32.dev)

## Build instruction

* Install and configure [Emscripten SDK](https://emscripten.org/index.html) (EMSDK)
* Download latest [Keystone](http://www.keystone-engine.org/)
* Download latest [Capstone](http://www.capstone-engine.org/)
* Compile and install Keystone using EMSDK
* Compile and install Capstone using EMSDK
* type `make` to build 
* To run locally, type `emrun .` 

To compile keystone/capstone (I am using `/usr/local/wasm` for the prefix, you can use any path, adjust `Makefile` if you use another path):

     mkdir build
     cd build
     emcmake cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr/local/wasm ..
     make && make install

Optional: to optimize the size, use [binaryen](https://github.com/WebAssembly/binaryen)

    wasm-opt -Oz casm.wasm  -o casm2.wasm
    mv casm2.wasm casm.wasm
    wasm-opt -Oz cdisasm.wasm  -o cdisasm2.wasm
    mv cdisasm.2wasm cdisasm.wasm

## License

Version 2 of the GNU General Public License (GPLv2). (I.e. Without the "any later version" clause.).
