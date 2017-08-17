#include "emu.h"
#include "plugin.h"

#include <vector>

bool g_EngineInit;
uc_engine* g_engine = NULL;
Capstone g_capstone;

// some logic for emulated code
bool isSegmentAccessed = false;
bool isSystemCall = false;


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
	_plugin_logprintf("About to start emulating address: %llx with %d bytes\n", start_addr, dataLen);

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
		//move to next instruction

		_plugin_logprintf("Instruction: %llx %s\n", start_addr, g_capstone.InstructionText(false).c_str());

		//Lets determine what needs to be prepared for the env

		for (auto i = 0; i < g_capstone.OpCount(); ++i)
		{
			duint dest = g_capstone.ResolveOpValue(i, [](x86_reg)->size_t
			{
				return 0;
			});
			// is this a destination outside of our module?

		}
		index += g_capstone.Size();
		start_addr += g_capstone.Size();

	
		
	}

	return true;
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