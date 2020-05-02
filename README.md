# Online assembler

## Build instruction

* Install and configure [Emscripten SDK](https://emscripten.org/index.html) (EMSDK)
* Download latest [Keystone](http://www.keystone-engine.org/)
* Compile and install Keystone using EMSDK
* type `make` to build `asm.c` to `index.wasm` and `index.js`
* To run locally, type `emrun .` 

To compile keystone (I am using `/wasm` for the prefix, you can use any path, adjust `Makefile` if you use another path):

     mkdir build
     cd build
     emcmake cmake -DCMAKE_INSTALL_PREFIX:PATH=/wasm ..
     make && make install


## License

Version 2 of the GNU General Public License (GPLv2). (I.e. Without the "any later version" clause.).
