#include "emu.h"
#include "plugin.h"
#include "EmuHooks.h"
#include "defines.h"
#include <vector>
#include <inttypes.h>

bool g_EngineInit; 
bool isDebugging;
uc_hook hookcode;
uc_hook hookMemInvalid;
uc_hook hookMem;
uc_engine* g_engine = NULL;
Capstone g_capstone;

std::vector<MEMACCESSINFO> memoryAccessList;
std::vector<DSTADDRINFO> destAddrInfoList;

bool InitEmuEngine()
{
    //initialize the engine 
	if (g_EngineInit || g_engine)
	{
		// close any previous running instances
		uc_err err = uc_close(g_engine);
	}
#ifdef _WIN64
	uc_err err = uc_open(UC_ARCH_X86, UC_MODE_64, &g_engine);
#else
    uc_err err = uc_open(UC_ARCH_X86, UC_MODE_32, &g_engine);
#endif
    if(err != UC_ERR_OK)
    {
        _plugin_logputs("Failed to load emu engine");
		g_EngineInit = false;
        return false;
    }
	g_EngineInit = true;
	_plugin_logputs("Emulation Engine Started!");
	
	//prepare the environment
    return true;
}

bool PrepareDataToEmulate(const unsigned char* data, size_t dataLen, duint start_addr, bool curCip = false)
{

	if (!isDebugging)
	{
		_plugin_logputs("not debugging..stopping");
		return false;
	}

	//clear our global vars
	destAddrInfoList.clear();
	memoryAccessList.clear();


	_plugin_logprintf("About to start emulating address: %08x with %u bytes\n", start_addr, dataLen);

	if (!g_EngineInit || !g_engine)
	{
		_plugin_logputs("Engine not started!");
		return false;
	}

	//iterate through the stream of data and disassemble
	for (size_t index = 0; index < dataLen; )
	{
		if (!g_capstone.Disassemble(start_addr, data + index))
		{
			// try reading forward: DANGER
			_plugin_logputs("Couldn't disassemble start of data, trying next byte..");
			start_addr++;
			index++;
			continue;
		}

		if (g_capstone.Size() == 0)
		{
			_plugin_logputs("Could not disassemble code");
			return false;
		}

		_plugin_logprintf("Instruction: %08X %s\n", start_addr, g_capstone.InstructionText(false).c_str());

		// Lets determine what needs to be prepared for the env
		// Here we determine the destination for any branches outside of emulated region.
		// Data accesses will be handled by hooks later in emulation
		if (g_capstone.InGroup(CS_GRP_CALL))
		{
			DSTADDRINFO dinfo;
			_plugin_logputs("Call instruction reached..");
			for (auto i = 0; i < g_capstone.OpCount(); ++i)
			{
				duint dest = g_capstone.ResolveOpValue(i, [](x86_reg)->size_t
				{
					return 0;
				});
				_plugin_logprintf("Destination to: %08X\n", dest);

				// is it a syscall?
				char modName[256];
				auto base = DbgFunctions()->ModBaseFromAddr(dest);
				DbgFunctions()->ModNameFromAddr(base, modName, true);
				auto party = DbgFunctions()->ModGetParty(base);
				
				dinfo.from = start_addr;
				dinfo.to = dest;
				dinfo.toMainMod = (party == 1) ? 0 : 1;

				_plugin_logprintf("Calling to module: %s\tIs call to system module: %d\n", modName, dinfo.toMainMod);
				// add it to our list of destination addresses
				destAddrInfoList.push_back(dinfo);
			}

		}
		else if (g_capstone.InGroup(CS_GRP_JUMP))
		{
			DSTADDRINFO dinfo;
			_plugin_logputs("jmp instruction reached..");
			for (auto i = 0; i < g_capstone.OpCount(); ++i)
			{
				duint dest = g_capstone.ResolveOpValue(i, [](x86_reg)->size_t
				{
					return 0;
				});
				_plugin_logprintf("Destination to: %08X\n", dest);

				// is it a syscall?
				char modName[256];
				auto base = DbgFunctions()->ModBaseFromAddr(dest);
				DbgFunctions()->ModNameFromAddr(base, modName, true);
				auto party = DbgFunctions()->ModGetParty(base);

				dinfo.from = start_addr;
				dinfo.to = dest;
				dinfo.toMainMod = (party == 1) ? 0 : 1;
				_plugin_logprintf("Jump to module: %s\tIs jump to system: %d\n", modName, dinfo.toMainMod);

				destAddrInfoList.push_back(dinfo);
			}

		}
		index += g_capstone.Size();
		start_addr += g_capstone.Size();
	}
	return true;
}

bool AddHooks(uc_engine* uc)
{
	// add code hook
	return false;
}

// returns stack base and limit for a specified thread ID
void EmuGetStackInfoForThread(duint threadId, STACKINFO & sinfo)
{
	if (!isDebugging)
	{
		_plugin_logputs("Not debugging");
		return;
	}
	PTEB teb = (PTEB)malloc(sizeof(TEB));
	memset(teb, 0, sizeof(TEB));

	// get stack info from teb
	auto teb_addr = DbgGetTebAddress(threadId);
	auto pid = DbgGetProcessId();
	DbgMemRead(teb_addr, teb, sizeof(TEB));
	auto *tib = (NT_TIB*)(teb);
	if (teb)
	{
		sinfo.base = (duint)tib->StackBase;
		sinfo.limit = (duint)tib->StackLimit;
		sinfo.tid = threadId;
	}
}

void EmuGetCurrentStackLimit(duint & limit)
{
	if (!isDebugging)
	{
		_plugin_logputs("Not debugging");
	}
	STACKINFO sinfo = { 0,0,0 };
	EmuGetStackInfoForThread(DbgGetThreadId(), sinfo);
	if (sinfo.limit)
	{
		limit = sinfo.limit;
	}
}

void EmuGetCurrentStackBase(duint & base)
{
	if (!isDebugging)
	{
		_plugin_logputs("Not debugging");
	}
	STACKINFO sinfo{ 0,0,0 };
	EmuGetStackInfoForThread(DbgGetThreadId(), sinfo);
	if (sinfo.base)
	{
		base = sinfo.base;
	}
}

// TODO: fix this (return in args)
bool EmuSetupRegs(uc_engine* uc, Cpu* cpu) 
{
	if (!isDebugging)
		return false;

	auto regWrite = [&uc](int regid, void* value)
	{
		uc_err err = uc_reg_write(uc, regid, value);
		if (err != UC_ERR_OK)
		{
			_plugin_logputs("Register write failed");
			return false;
		}	
		return true;
	};

#ifdef _WIN64
	regWrite(UC_X86_REG_RAX, (void*)cpu->getCAX());
	regWrite(UC_X86_REG_RCX, (void*)cpu->getCCX());
	regWrite(UC_X86_REG_RBX, (void*)cpu->getCBX());
	regWrite(UC_X86_REG_RDX, (void*)cpu->getCDX());
	regWrite(UC_X86_REG_RSI, (void*)cpu->getCSI());
	regWrite(UC_X86_REG_RDI, (void*)cpu->getCDI());
	regWrite(UC_X86_REG_RBP, (void*)cpu->getCBP());
	regWrite(UC_X86_REG_RSP, (void*)cpu->getCSP());
	
#else
	regWrite(UC_X86_REG_EAX, (void*)cpu->getCAX());
	regWrite(UC_X86_REG_ECX, (void*)cpu->getCCX());
	regWrite(UC_X86_REG_EBX, (void*)cpu->getCBX());
	regWrite(UC_X86_REG_EDX, (void*)cpu->getCDX());
	regWrite(UC_X86_REG_ESI, (void*)cpu->getCSI());
	regWrite(UC_X86_REG_EDI, (void*)cpu->getCDI());
	regWrite(UC_X86_REG_EBP, (void*)cpu->getCBP());
	regWrite(UC_X86_REG_ESP, (void*)cpu->getCSP());
#endif

	regWrite(UC_X86_REG_GS, (void*)cpu->getGS());
	regWrite(UC_X86_REG_CS, (void*)cpu->getCS());
	regWrite(UC_X86_REG_FS, (void*)cpu->getFS());
	regWrite(UC_X86_REG_SS, (void*)cpu->getSS());
	
}

bool EmulateData(uc_engine* uc, const unsigned char* data, size_t size, duint start_address, bool nullInit)
{
	if (!isDebugging)
		return false;

	uc_err err;
	// set up current registers and stack mem
	Cpu cpu;

	// For segment registers (probably switch to this eventually)
	REGDUMP rDump;
	DbgGetRegDump(&rDump);

#ifdef _WIN64
	cpu.setCAX(Script::Register::GetRAX());
	cpu.setCBX(Script::Register::GetRBX());
	cpu.setCCX(Script::Register::GetRCX());
	cpu.setCDI(Script::Register::GetRDI());
	cpu.setCDX(Script::Register::GetRDX());
	cpu.setCSI(Script::Register::GetRSI());
	cpu.setCSP(Script::Register::GetRSP());
	cpu.setCBP(Script::Register::GetRBP());

	cpu.setR8(Script::Register::GetR8());
	cpu.setR9(Script::Register::GetR9());
	cpu.setR10(Script::Register::GetR10());
	cpu.setR11(Script::Register::GetR11());
	cpu.setR12(Script::Register::GetR12());
	cpu.setR13(Script::Register::GetR13());
	cpu.setR14(Script::Register::GetR14());
	cpu.setR15(Script::Register::GetR15());
#else
	cpu.setCAX(Script::Register::GetEAX());
	cpu.setCBX(Script::Register::GetEBX());
	cpu.setCCX(Script::Register::GetECX());
	cpu.setCDI(Script::Register::GetEDI());
	cpu.setCDX(Script::Register::GetEDX());
	cpu.setCSI(Script::Register::GetESI());
	cpu.setCSP(Script::Register::GetESP());
	cpu.setCBP(Script::Register::GetEBP());
#endif
	// segment
	cpu.setCS(rDump.regcontext.cs);
	cpu.setGS(rDump.regcontext.gs);
	cpu.setFS(rDump.regcontext.fs);
	cpu.setSS(rDump.regcontext.ss);

	cpu.setEFLAGS(Script::Register::GetCFLAGS());
	cpu.setCIP(start_address);

	// TODO: set up segment selectors
	uc_x86_mmr gdtr;
	duint r_cs;
	duint r_ss;
	duint r_fs;
	duint r_gs;
	duint r_es;
	duint r_ds;

	//set up our hooks
	err = uc_hook_add(uc, &hookcode, UC_HOOK_CODE, EmuHookCode, nullptr, start_address, start_address + size);
	if (err != UC_ERR_OK)
	{
		_plugin_logputs("Failed to register code hook");
		return false;
	}
	err = uc_hook_add(uc, &hookMemInvalid, UC_HOOK_MEM_INVALID, EmuHookMemInvalid, nullptr, 1, 0);
	if (err != UC_ERR_OK)
	{
		_plugin_logputs("Failed to register mem invalid hook");
		return false;
	}
	err = uc_hook_add(uc, &hookMem, UC_HOOK_MEM_WRITE, EmuHookMem, nullptr, 1, 0);
	if (err != UC_ERR_OK)
	{
		_plugin_logputs("Failed to register mem write\n");
		return false;
	}

	//stack limit
	duint slimit;
	EmuGetCurrentStackLimit(slimit);
	_plugin_logprintf("Stack Limit: %x\n", slimit);

	// map our stack and point to CSP
	auto stack_addr = cpu.getCSP();
	auto stack_aligned = PAGE_ALIGN(stack_addr);
	_plugin_logprintf("Aligned stack address: %d\n", stack_aligned);
	err = uc_mem_map_ptr(uc, stack_aligned, ROUND_TO_PAGES(slimit), UC_PROT_READ | UC_PROT_WRITE, &stack_addr);
	if (err != UC_ERR_OK)
	{
		_plugin_logputs("Memory Map for stack failed\n");
		return false;
	}

	//map memory for our code
	auto aligned_address = PAGE_ALIGN(start_address);
	size_t filler_size = start_address - aligned_address;
	err = uc_mem_map(uc, aligned_address, ROUND_TO_PAGES(size + filler_size), UC_PROT_ALL);
	if (err != UC_ERR_OK)
	{
		_plugin_logprintf("MAP ERROR: %s\n", uc_strerror(uc_errno(uc)));
		_plugin_logputs("Memory map failed for code");
		return false;
	}

	char *filler = (char*)malloc(filler_size);
	memset(filler, 0x90, filler_size);
	//filler for code
	err = uc_mem_write(uc, aligned_address, filler, filler_size);
	if (err != UC_ERR_OK)
	{
		_plugin_logputs("Failed to write filler bytes");
		free(filler);
		return false;
	}
	//write code
	err = uc_mem_write(uc, aligned_address + filler_size, data, size);
	if (err != UC_ERR_OK)
	{
		_plugin_logputs("writing code failed");
		free(filler);
		return false;
	}

	// setup the registers
	if (!EmuSetupRegs(uc, &cpu))
	{
		_plugin_logputs("Register setups failed");
		return false;
	}

	// STARRRRTTTT
	err = uc_emu_start(uc, start_address, start_address + size, 0, 0);
	if (err != UC_ERR_OK)
	{
		_plugin_logputs("Something weird happend with emulation start");
	}


	return true;

}

void CleanupEmuEngine()
{
	if (g_engine)
	{
		uc_close(g_engine);
	}
}