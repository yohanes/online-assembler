/* This file is part of the online assembler distribution (https://github.com/yohanes/online-assembler).
 * Copyright (c) 2020 Yohanes Nugrooh.
 * 
 * This program is free software: you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by  
 * the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <errno.h>
#include <limits.h>
#include <string>
#include <unistd.h>
#include <capstone/capstone.h>
#include <string>

static std::string tohexstring(uint8_t *bytes, int size){
		char buf[4];
		std::string result;
		for (int i = 0; i < size; i++)
		{
			if (i>0)
				result += " ";
			snprintf(buf, sizeof(buf), "%02x", bytes[i]);
			result += buf;
		}
		return result;
}
static int hex2dec(char hex)
{
	if (hex>='0' && hex<='9')
		return hex-'0';
	
	if (hex >= 'A' && hex <= 'F') 
		return 10 + (hex-'A');

	if (hex >= 'a' && hex <= 'f') 
		return 10 + (hex-'a');

	return -1;
}

static const unsigned char *decode_hex(const char *x)
{
	int len = strlen(x);
	unsigned char *result = (unsigned char*)calloc(1, (len/2)+1);
	int j = 0;
	for (int i =0; i < len; i+=2){
		int c1 = hex2dec(x[i]);
		int c2 = hex2dec(x[i+1]);
		if (c1==-1 || c2==-1) {
			free(result);
			return 0;
		}

		unsigned char c = ( c1 << 4 )|c2;
		result[j++] = c;
	}
	return result;
}


/*codehex must be valid hex*/
extern "C" {
const char *disassemble(const char *_arch_mode, const char *codehex, uint64_t start_addr)
{
	static char *result;
	csh handle;
	cs_insn *insn;
	size_t count;

	cs_arch arch = CS_ARCH_X86;
	cs_mode mode = CS_MODE_64;

	if (result)
		free(result);

	const unsigned char * code = decode_hex(codehex);

	if (!code) {
		result = strdup("{\"error\": 1, \"message\": \"ERROR in hex decode\"}");
		return result;		
	}

	std::string arch_mode = _arch_mode;

	if (arch_mode=="arm") {
		arch = CS_ARCH_ARM;
		mode = CS_MODE_ARM;
	}

	if (arch_mode=="arm64") {
		arch = CS_ARCH_ARM64;
		mode = CS_MODE_ARM;
	}

	if (arch_mode=="thumb") {
		arch = CS_ARCH_ARM;
		mode = CS_MODE_THUMB;
	}

	if (arch_mode=="thumbbe") {
		arch = CS_ARCH_ARM;
		mode = (cs_mode)(CS_MODE_THUMB|CS_MODE_BIG_ENDIAN);
	}

	if (arch_mode=="mips32") {
		arch = CS_ARCH_MIPS;
		mode = CS_MODE_MIPS32;
	}

	if (arch_mode=="mips32be") {
		arch = CS_ARCH_MIPS;
		mode = (cs_mode)(CS_MODE_MIPS32|CS_MODE_BIG_ENDIAN);
	}

	if (arch_mode=="mips32r6") {
		arch = CS_ARCH_MIPS;
		mode = CS_MODE_MIPS32R6;
	}

	if (arch_mode=="mips64") {
		arch = CS_ARCH_MIPS;
		mode = CS_MODE_MIPS64;
	}
	if (arch_mode=="mips64be") {
		arch = CS_ARCH_MIPS;
		mode = (cs_mode)(CS_MODE_MIPS64|CS_MODE_BIG_ENDIAN);
	}


	if (arch_mode=="ppc32") {
		arch = CS_ARCH_PPC;
		mode = CS_MODE_32;
	}

	if (arch_mode=="ppc64") {
		arch = CS_ARCH_PPC;
		mode = CS_MODE_64;
	}

	if (arch_mode=="sparc") {
		arch = CS_ARCH_SPARC;
		mode = CS_MODE_LITTLE_ENDIAN; //default
	}

	if (arch_mode=="sparcbe") {
		arch = CS_ARCH_SPARC;
		mode = CS_MODE_V9; //default
	}

	if (arch_mode=="systemz") {
		arch = CS_ARCH_SYSZ;
		mode = CS_MODE_LITTLE_ENDIAN;
	}

	if (arch_mode=="xcore") {
		arch = CS_ARCH_XCORE;
		mode = CS_MODE_LITTLE_ENDIAN;
	}

	if (arch_mode=="x86_16") {
		arch = CS_ARCH_X86;
		mode = CS_MODE_16;
	}

	if (arch_mode=="x86_32") {
		arch = CS_ARCH_X86;
		mode = CS_MODE_32;
	}


	if (arch_mode=="x86_64") {
		arch = CS_ARCH_X86;
		mode = CS_MODE_64;
	}

	if (arch_mode=="evm") {
		arch = CS_ARCH_EVM;
		mode = CS_MODE_LITTLE_ENDIAN;
	}	

	if (cs_open(arch, mode, &handle) != CS_ERR_OK) {
		result = strdup("{\"error\": 1, \"message\": \"ERROR in cs_open\"}");
		return result;
	}
	cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);

	int len = strlen(codehex)/2;
	
	count = cs_disasm(handle, code, len, start_addr, 0, &insn);

	std::string res = "{\"error\": 0, \"instructions\":[";

	if (count > 0) {

		for (size_t j = 0; j < count; j++) {

			if (j>0)
				res += "," ;

			res += "{";

			char addr[128];
			snprintf(addr, sizeof(addr), "0x%" PRIx64, insn[j].address);
			res += "\"address\":\"";
			res += addr;
			res += "\",\n" ;
			res += "\"bytes\":\"";
			res += tohexstring(insn[j].bytes, insn[j].size);
			res += "\",\n" ;
			res += "\"mnemonic\":\"";
			res += insn[j].mnemonic;
			res +=  +"\",\n" ;
			res += "\"opstr\":\"";
			res += insn[j].op_str;
			res += "\"\n" ;
			res += "}";
		}
		
		cs_free(insn, count);
	}

	res += "]\n}\n";

	cs_close(&handle);

	result = strdup(res.c_str());

	return result;
}

}