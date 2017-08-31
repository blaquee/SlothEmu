#pragma once
#include "emu.h"

void HookInstructions(uc_engine* uc, duint address, size_t size, void* userdata);
static bool HookMemInvalid(uc_engine* uc, uc_mem_type type, duint address, int size, int64_t value, void* userdata);
static void HookMem(uc_engine* uc, uc_mem_type type, duint address, int size, int64_t value, void* userdata);