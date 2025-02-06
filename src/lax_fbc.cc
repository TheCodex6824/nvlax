/*  This file is part of nvlax.

    nvlax is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    THIS SOFTWARE IS PROVIDED 'AS-IS', WITHOUT ANY EXPRESS
    OR IMPLIED WARRANTY. IN NO EVENT WILL THE AUTHORS BE HELD
    LIABLE FOR ANY DAMAGES ARISING FROM THE USE OF THIS SOFTWARE.  */

#include <array>
#include <cstdint>
#include <iostream>
#include <unordered_set>

#include <LIEF/ELF.hpp>
#include <Zydis/Zydis.h>
#include <ppk_assert.h>

#include "common.h"

const char *app_name = "nvlax_fbc";
const char *lib_name = "libnvidia-fbc.so.XXX";

static bool find_string_xref(ZydisDecoder& decoder, const char* str, const LIEF::Section* rodata, const LIEF::Section* text, ZyanU64& out_addr)
{
    ZyanU64 offset = rodata->virtual_address() + rodata->search(str);

    auto content = text->content();
    const uint8_t *data = content.data();
    ZyanUSize length = content.size();

    bool found = false;
    ZydisDecodedInstruction instr;
    std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT> operands;
    while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, data, length, &instr, operands.data()))) {
        if (instr.mnemonic == ZYDIS_MNEMONIC_LEA) {
            ZyanU64 temp = text->virtual_address() +
                          (data - content.data() + instr.length) +
                          operands[1].mem.disp.value;

            if (temp == offset) {
                found = true;
                out_addr = text->virtual_address() + data - content.data();
                break;
            }
        }

        data += instr.length;
        length -= instr.length;
    }

    return found;
}

static bool find_call_dest(ZydisDecoder& decoder, ZyanU64 start, const LIEF::Section* text, ZyanU64& out_addr)
{
    auto content = text->content();
    const uint8_t *data = content.data() + (start - text->virtual_address());
    ZyanUSize length = content.size();

    ZydisDecodedInstruction instr;
    std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT> operands;
    bool found = false;
    while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, data, length, &instr, operands.data()))) {
        if (instr.mnemonic == ZYDIS_MNEMONIC_CALL && ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instr, &operands[0], text->virtual_address() + (data - content.data()), &out_addr))) {
            found = true;
            break;
        }

        data += instr.length;
        length -= instr.length;
    }

    return found;
}

static const std::unordered_set<ZydisMnemonic> JUMP_MNEMONICS = { ZYDIS_MNEMONIC_JB, ZYDIS_MNEMONIC_JBE, ZYDIS_MNEMONIC_JCXZ, ZYDIS_MNEMONIC_JECXZ, ZYDIS_MNEMONIC_JL,
                                                                 ZYDIS_MNEMONIC_JLE, ZYDIS_MNEMONIC_JMP, ZYDIS_MNEMONIC_JNB, ZYDIS_MNEMONIC_JNBE, ZYDIS_MNEMONIC_JNL,
                                                                 ZYDIS_MNEMONIC_JNLE, ZYDIS_MNEMONIC_JNO, ZYDIS_MNEMONIC_JNP, ZYDIS_MNEMONIC_JNS, ZYDIS_MNEMONIC_JNZ,
                                                                 ZYDIS_MNEMONIC_JO, ZYDIS_MNEMONIC_JP, ZYDIS_MNEMONIC_JS, ZYDIS_MNEMONIC_JZ };

static bool find_jump(ZydisDecoder& decoder, ZyanU64 start, const LIEF::Section* text, ZyanU64 jump_target, ZyanU64& jump_out, ZyanUSize& jump_size)
{
    auto content = text->content();
    const uint8_t *data = content.data() + (start - text->virtual_address());
    ZyanUSize length = content.size();

    ZydisDecodedInstruction instr;
    std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT> operands;
    bool found = false;
    while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, data, length, &instr, operands.data()))) {
        if (JUMP_MNEMONICS.find(instr.mnemonic) != JUMP_MNEMONICS.end()) {
            ZyanU64 addr;
            ZyanU64 offset = text->virtual_address() + (data - content.data());
            if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instr,
                                                       &operands[0],
                                                       offset,
                                                       &addr)) && addr == jump_target)
            {
                jump_out = offset;
                jump_size = instr.length;
                found = true;
                break;
            }
        }

        data += instr.length;
        length -= instr.length;
    }

    return found;
}

constexpr const char* EGL_LIB_STRING = "libEGL_nvidia.so.0";
constexpr const char* UNSUPPORTED_HW_STRING = "This hardware does not support NvFBC";
int
main (int argc,
      char **argv)
{
    std::string_view input, output;
    if (!parse_args(argc, argv, input, output)) {
        return EXIT_FAILURE;
    }

    auto bin = LIEF::ELF::Parser::parse(input.data());

    std::cout << "[+] libnvidia-fbc.so\n";

    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    // basic outline of patch strategy:
    // 1. find address of start of function to patch
    // 2. find branch target we want to make inaccessible
    // 3. patch jump leading to that branch
    // we have to find the start of the function because it is impossible to go backwards in an x86 instruction stream,
    // which is why the jump offset used to be hardcoded instead of searched for
    const auto* s_rodata = bin->get_section(".rodata");
    const auto* s_text = bin->get_section(".text");

    // find string near call of function we want to patch
    ZyanU64 libegl_offset = 0;
    bool found = find_string_xref(decoder, EGL_LIB_STRING, s_rodata, s_text, libegl_offset);
    PPK_ASSERT_ERROR(found, "Could not locate string \"%s\" in binary", EGL_LIB_STRING);

    // use previous string xref to find actual address of function we want to patch
    // assumes the next call after string xref is the call to the target function
    ZyanU64 target_offset = 0;
    found = find_call_dest(decoder, libegl_offset, s_text, target_offset);
    PPK_ASSERT_ERROR(found, "Could not find call to patch target function");

    // find branch target to patch out
    ZyanU64 lea_offset = 0;
    found = find_string_xref(decoder, UNSUPPORTED_HW_STRING, s_rodata, s_text, lea_offset);
    PPK_ASSERT_ERROR(found, "Could not locate string \"%s\" in binary", UNSUPPORTED_HW_STRING);

    // find jump to branch target
    // assumes the jump goes directly to the lea instruction found previously
    ZyanU64 jump_offset = 0;
    ZyanUSize jump_size = 0;
    found = find_jump(decoder, target_offset, s_text, lea_offset, jump_offset, jump_size);
    PPK_ASSERT_ERROR(found, "Could not locate jump patch target");

    // NOP the jump
    bin->patch_address(jump_offset,
                       std::vector<std::uint8_t>(jump_size, 0x90));
    bin->write(output.data());
    std::cout << "[+] patched successfully" << std::endl;

    return EXIT_SUCCESS;
}
