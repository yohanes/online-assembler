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
#include <unistd.h>
#include <keystone/keystone.h>

/* returns hex encoded string, in case of error, will return ERROR: <message>*/
const char *assemble(const char *mode, const char *assembly, uint64_t start_addr)
{
	static char*result;
	ks_engine *ks;	
	ks_err err = KS_ERR_ARCH;
	unsigned char *insn;
	size_t size;
	size_t count;
	
	
	if (!strcmp(mode, "x16")) {
		err = ks_open(KS_ARCH_X86, KS_MODE_16, &ks);
	}
	if (!strcmp(mode, "x32")) {
		err = ks_open(KS_ARCH_X86, KS_MODE_32, &ks);
	}
	if (!strcmp(mode, "x64")) {
		err = ks_open(KS_ARCH_X86, KS_MODE_64, &ks);
	}
	
	if (!strcmp(mode, "x16att")) {
		err = ks_open(KS_ARCH_X86, KS_MODE_16, &ks);
		if (!err) {
			ks_option(ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_ATT);
		}
	}
	if (!strcmp(mode, "x32att")) {
		err = ks_open(KS_ARCH_X86, KS_MODE_32, &ks);
		if (!err) {
			ks_option(ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_ATT);
		}
	}
	if (!strcmp(mode, "x64att")) {
		err = ks_open(KS_ARCH_X86, KS_MODE_64, &ks);
		if (!err) {
			ks_option(ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_ATT);
		}
	}
	
	if (!strcmp(mode, "x16nasm")) {
		err = ks_open(KS_ARCH_X86, KS_MODE_16, &ks);
		if (!err) {
			ks_option(ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_NASM);
		}
	}
	if (!strcmp(mode, "x32nasm")) {
		err = ks_open(KS_ARCH_X86, KS_MODE_32, &ks);
		if (!err) {
			ks_option(ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_NASM);
		}
	}
	if (!strcmp(mode, "x64nasm")) {
		err = ks_open(KS_ARCH_X86, KS_MODE_64, &ks);
		if (!err) {
			ks_option(ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_NASM);
		}
	}
	
	if (!strcmp(mode, "arm")) {
		err = ks_open(KS_ARCH_ARM, KS_MODE_ARM+KS_MODE_LITTLE_ENDIAN, &ks);
	}
	
	if (!strcmp(mode, "armbe")) {
		err = ks_open(KS_ARCH_ARM, KS_MODE_ARM+KS_MODE_BIG_ENDIAN, &ks);
	}
	
	if (!strcmp(mode, "thumb")) {
		err = ks_open(KS_ARCH_ARM, KS_MODE_THUMB+KS_MODE_LITTLE_ENDIAN, &ks);
	}

	if (!strcmp(mode, "thumbbe")) {
		err = ks_open(KS_ARCH_ARM, KS_MODE_THUMB+KS_MODE_BIG_ENDIAN, &ks);
	}
	
	if (!strcmp(mode, "arm64")) {
		err = ks_open(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, &ks);
	}
	
	if (!strcmp(mode, "hex") || !strcmp(mode, "hexagon")) {
		err = ks_open(KS_ARCH_HEXAGON, KS_MODE_BIG_ENDIAN, &ks);
	}
	
	if (!strcmp(mode, "mips")) {
		err = ks_open(KS_ARCH_MIPS, KS_MODE_MIPS32+KS_MODE_LITTLE_ENDIAN, &ks);
	}
	
	if (!strcmp(mode, "mipsbe")) {
		err = ks_open(KS_ARCH_MIPS, KS_MODE_MIPS32+KS_MODE_BIG_ENDIAN, &ks);
	}
	
	if (!strcmp(mode, "mips64")) {
		err = ks_open(KS_ARCH_MIPS, KS_MODE_MIPS64+KS_MODE_LITTLE_ENDIAN, &ks);
	}
	
	if (!strcmp(mode, "mips64be")) {
		err = ks_open(KS_ARCH_MIPS, KS_MODE_MIPS64+KS_MODE_BIG_ENDIAN, &ks);
	}
	
	if (!strcmp(mode, "ppc32be")) {
		err = ks_open(KS_ARCH_PPC, KS_MODE_PPC32+KS_MODE_BIG_ENDIAN, &ks);
	}
	
	if (!strcmp(mode, "ppc64")) {
		err = ks_open(KS_ARCH_PPC, KS_MODE_PPC64+KS_MODE_LITTLE_ENDIAN, &ks);
	}
	
	if (!strcmp(mode, "ppc64be")) {
		err = ks_open(KS_ARCH_PPC, KS_MODE_PPC64+KS_MODE_BIG_ENDIAN, &ks);
	}
	
	if (!strcmp(mode, "sparc")) {
		err = ks_open(KS_ARCH_SPARC, KS_MODE_SPARC32+KS_MODE_LITTLE_ENDIAN, &ks);
	}

	if (!strcmp(mode, "sparcbe")) {
		err = ks_open(KS_ARCH_SPARC, KS_MODE_SPARC32+KS_MODE_BIG_ENDIAN, &ks);
	}

	if (!strcmp(mode, "sparc64")) {
		err = ks_open(KS_ARCH_SPARC, KS_MODE_SPARC64+KS_MODE_LITTLE_ENDIAN, &ks);
	}

	if (!strcmp(mode, "sparc64be")) {
		err = ks_open(KS_ARCH_SPARC, KS_MODE_SPARC64+KS_MODE_BIG_ENDIAN, &ks);
	}

	if (!strcmp(mode, "systemz") || !strcmp(mode, "sysz") || !strcmp(mode, "s390x")) {
		err = ks_open(KS_ARCH_SYSTEMZ, KS_MODE_BIG_ENDIAN, &ks);
	}

	if (ks_asm(ks, assembly, start_addr, &insn, &size, &count)) {		
		if (result)
			free(result);
		result = (char *)malloc(2048);
		snprintf(result, 2048, "ERROR: failed on ks_asm() with count = %zu, error = '%s' (code = %u)\n", count, ks_strerror(ks_errno(ks)), ks_errno(ks));
	} else {
		size_t i;

		result = (char *)realloc(result, 4*size+1);
		memset(result, 0, 4*size+1);
		char buf[4];
		result[0] = '\0';
		for (i = 0; i < size; i++) {
			if (i>0)
				strcat(result, " ");
			snprintf(buf, sizeof(buf), "%02x", insn[i]);
			strcat(result, buf);
		}
	}
	ks_free(insn);	
	ks_close(ks);
	return result;
}