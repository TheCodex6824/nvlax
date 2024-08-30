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

#include <LIEF/ELF.hpp>
#include <Zydis/Zydis.h>
#include <ppk_assert.h>

#include "common.h"

using namespace LIEF::ELF;

const char *app_name = "nvlax_fbc";
const char *lib_name = "libnvidia-fbc.so.XXX";

struct JumpPatchInfo
{
    ZydisMnemonic jump_op;
    size_t jump_offset;
    size_t jump_size;
    std::string_view desc;
};

const std::array<JumpPatchInfo, 3> possible_patches =
{{
    {ZYDIS_MNEMONIC_JNZ, 0x102, 6, "[560, )"},
    {ZYDIS_MNEMONIC_JNZ, 0xA1, 6, "[555, 560)"},
    {ZYDIS_MNEMONIC_JNB, 0x0A, 2, "[535, 555)"}
}};

int
main (int argc,
      char **argv)
{
    std::string_view input, output;
    if (!parse_args(argc, argv, input, output)) {
        return EXIT_FAILURE;
    }

    auto bin = Parser::parse(input.data());

    size_t offset;

    {
        auto s_rodata = bin->get_section(".rodata");
        offset = s_rodata->virtual_address() + s_rodata->search("This hardware does not support NvFBC");
    }

    std::cout << "[+] libnvidia-fbc.so\n";

    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    bool found = false;

    {
        auto s_text = bin->get_section(".text");
        auto v_text_content = s_text->content();

        const uint8_t *data = v_text_content.data();
        ZyanUSize length = v_text_content.size();

        // find the only x-ref to the string above
        ZydisDecodedInstruction instr;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
        while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, data, length, &instr, operands))) {
            if (instr.mnemonic == ZYDIS_MNEMONIC_LEA) {
                size_t temp = s_text->virtual_address() +
                              (data - v_text_content.data() + instr.length) +
                              operands[1].mem.disp.value;

                if (temp == offset) {
                    found = true;
                    offset = s_text->virtual_address() + data - v_text_content.data();
                    break;
                }
            }

            data += instr.length;
            length -= instr.length;
        }
    }

    PPK_ASSERT_ERROR(found);

    bool success = false;
    for (const auto& patch : possible_patches)
    {
        auto v_backtrack_bytes = bin->get_content_from_virtual_address(offset - patch.jump_offset,
                                                                           patch.jump_size);

        ZydisDecodedInstruction instr;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder,
                                                 v_backtrack_bytes.data(),
                                                 v_backtrack_bytes.size(),
                                                 &instr,
                                                 operands)))
        {
            continue;
        }



        if (instr.mnemonic != patch.jump_op)
        {
            continue;
        }

        ZyanU64 addr;
        if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instr,
                                                   &operands[0],
                                                   offset - patch.jump_offset,
                                                   &addr)))
        {
            continue;
        }

        // hopefully more fail-safe
        // leaving this as an assert because this should always pass if it gets here
        PPK_ASSERT_ERROR(addr == offset);

        // NOP the jump
        bin->patch_address(offset - patch.jump_offset,
                           std::vector<std::uint8_t>(patch.jump_size, 0x90));
        bin->write(output.data());
        std::cout << "[+] patched successfully with patch \"" << patch.desc << "\"" << std::endl;
        success = true;
        break;
    }

    int retval = EXIT_SUCCESS;
    if (!success)
    {
        std::cerr << "[+] all possible patches failed" << std::endl;
        retval = EXIT_FAILURE;
    }

    return retval;
}
