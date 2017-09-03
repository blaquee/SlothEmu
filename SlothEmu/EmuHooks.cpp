#include "EmuHooks.h"

void HookInstructions(uc_engine* uc, duint addr, size_t size, void* userdata)
{
	duint curRip;
	uc_reg_read(uc, UC_X86_REG_RIP, &curRip);
	_plugin_logprintf("executing instruction at 0x%X, size: %u", addr, size);
	// callback
	// OnInstructionExecute();
	return;
}

// return false to stop emulation
static bool HookMemInvalid(uc_engine* uc, uc_mem_type type, duint address, int size, int64_t value, void* userdata)
{
	switch (type)
	{
	default:
		return false;
	case UC_MEM_WRITE_UNMAPPED:
		_plugin_logputs("Unmapped memory reached");
		return false;
	}
	return true;
}

void HookMem(uc_engine* uc, uc_mem_type type, duint address, int size, int64_t value, void* userdata)
{
	switch (type)
	{
	default:break;
	case UC_MEM_READ:
		_plugin_logprintf("Reading Memory at: %X size: %u", address, size);
		break;
	case UC_MEM_WRITE:
		_plugin_logprintf("Writing to Memory at: %X, value: %X, size: %u", address, value, size);
		break;
	}
	return;
}

