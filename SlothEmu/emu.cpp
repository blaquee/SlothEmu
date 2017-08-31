#include "emu.h"
#include "plugin.h"

#include <vector>
#include <inttypes.h>

bool g_EngineInit; 
bool isDebugging;
uc_engine* g_engine = NULL;
Capstone g_capstone;

std::vector<MEMACCESSINFO> memoryAccessList;
std::vector<DSTADDRINFO> destAddrInfoList;

// some logic for emulated code
bool isSegmentAccessed = false;
bool isSystemCall = false;

static void CodeHook(uc_engine* uc, duint address, size_t size, void* userdata)
{
	_plugin_logprintf("Executing code at 0x%X, length = 0x%X\n", address, size);
}

bool InitEmuEngine()
{
    //initialize the engine 
    uc_err err = uc_open(UC_ARCH_X86, UC_MODE_32, &g_engine);
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
	isSegmentAccessed = false;
	isSystemCall = false;


	_plugin_logprintf("About to start emulating address: %08x with %x bytes\n", start_addr, dataLen);

	// disassemble and determine if code accesses any segments we need to setup or syscalls
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
				isSystemCall = (party == 1) ? 1 : 0;
				
				dinfo.from = start_addr;
				dinfo.to = dest;
				dinfo.toMainMod = !isSystemCall;

				_plugin_logprintf("Calling to module: %s\tIs call to system module: %d\n", modName, isSystemCall);
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
				isSystemCall = (party == 1) ? 1 : 0;

				dinfo.from = start_addr;
				dinfo.to = dest;
				dinfo.toMainMod = !isSystemCall;
				_plugin_logprintf("Jump to module: %s\tIs jump to system: %d\n", modName, isSystemCall);

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

}

duint GetCurrentStack();
duint GetStackLimitForThread(duint threadId, )
{
	if (!isDebugging)
		return 0;
	//get the current threads TEB, for stack base and limit
	PTEB teb = (PTEB)DbgGetTebAddress(threadId);
	if (teb)
	{

	}

}
bool EmulateData(const char* data, size_t size, duint start_address)
{
	if (!isDebugging)
		return false;
	uc_err error;

}

void CleanupEmuEngine()
{
	if (g_engine)
	{
		uc_close(g_engine);
	}
}

bool SetupEnvironment(uc_engine* eng, duint threadID)
{
	_plugin_logputs("setup environment impl");
    return false;
}

bool SetupDescriptorTable(uc_engine* eng)
{
    return false;
}

bool SetupContext(uc_engine* eng)
{
    return false;
}

bool SetupStack(uc_engine* eng)
{
	return false;
}