#pragma once
#include "emu.h"

void EmuHookCode(uc_engine* uc, duint address, size_t size, void* userdata);
bool EmuHookMemInvalid(uc_engine* uc, uc_mem_type type, duint address, int size, int64_t value, void* userdata);
void EmuHookMem(uc_engine* uc, uc_mem_type type, duint address, int size, int64_t value, void* userdata);