/*
 * test_tinydis.c - tests for the tiny disassembler.
 */

#include <stdio.h>
#include <string.h>

#include "zdbg_tinyasm.h"
#include "zdbg_tinydis.h"

static int failures;

#define CHECK(cond) do {                                              \
	if (!(cond)) {                                                \
		fprintf(stderr, "FAIL %s:%d: %s\n",                   \
		    __FILE__, __LINE__, #cond);                       \
		failures++;                                           \
	}                                                             \
} while (0)

static void
test_fixed(void)
{
	struct ztinydis d;
	uint8_t buf[6];

	buf[0] = 0x90;
	CHECK(ztinydis_one(0x400000, buf, 1, &d) == 0);
	CHECK(d.len == 1);
	CHECK(strcmp(d.text, "nop") == 0);

	buf[0] = 0xcc;
	CHECK(ztinydis_one(0x400000, buf, 1, &d) == 0);
	CHECK(strcmp(d.text, "int3") == 0);

	buf[0] = 0xc3;
	CHECK(ztinydis_one(0x400000, buf, 1, &d) == 0);
	CHECK(strcmp(d.text, "ret") == 0);
}

static void
test_unknown(void)
{
	struct ztinydis d;
	uint8_t buf[1];
	buf[0] = 0x55;
	CHECK(ztinydis_one(0x400000, buf, 1, &d) == 0);
	CHECK(d.len == 1);
	CHECK(strcmp(d.text, "db 0x55") == 0);
}

static void
test_roundtrip(void)
{
	struct ztinyasm enc;
	struct ztinydis d;

	/* jmp rel32 */
	CHECK(ztinyasm_assemble(0x401000, "jmp 0x401080", &enc, NULL) == 0);
	CHECK(ztinydis_one(0x401000, enc.code, enc.len, &d) == 0);
	CHECK(d.len == 5);
	CHECK(strstr(d.text, "jmp") != NULL);
	CHECK(strstr(d.text, "401080") != NULL);

	/* jmp8 */
	CHECK(ztinyasm_assemble(0x401000, "jmp8 0x401010", &enc, NULL) == 0);
	CHECK(ztinydis_one(0x401000, enc.code, enc.len, &d) == 0);
	CHECK(d.len == 2);
	CHECK(strstr(d.text, "jmp8") != NULL);
	CHECK(strstr(d.text, "401010") != NULL);

	/* jz rel32 */
	CHECK(ztinyasm_assemble(0x401000, "jz 0x401080", &enc, NULL) == 0);
	CHECK(ztinydis_one(0x401000, enc.code, enc.len, &d) == 0);
	CHECK(d.len == 6);
	CHECK(strstr(d.text, "jz") != NULL);

	/* jnz8 */
	CHECK(ztinyasm_assemble(0x401000, "jnz8 0x401010", &enc, NULL) == 0);
	CHECK(ztinydis_one(0x401000, enc.code, enc.len, &d) == 0);
	CHECK(d.len == 2);
	CHECK(strstr(d.text, "jnz8") != NULL);
}

int
main(void)
{
	test_fixed();
	test_unknown();
	test_roundtrip();

	if (failures) {
		fprintf(stderr, "%d failure(s)\n", failures);
		return 1;
	}
	printf("test_tinydis ok\n");
	return 0;
}
