#pragma once

#include "unicorn/unicorn.h"
#include "capstone_wrapper/capstone_wrapper.h"
#include "defines.h"
#include "plugin.h"
#include <vector>

// Work on this later
namespace engine
{
	class EmuEngine
	{
	private:
		uc_engine* eng = nullptr;
		bool mEngineInit;
		bool mStackInit;
		bool mGdtInit;
		bool mFsSegInit;
		bool mGsSegInit;
		bool mLightEmu;

		std::vector<unsigned char> data;

	public:
		EmuEngine::EmuEngine() {}
		virtual ~EmuEngine();
	};

}

// How we want to emulate
enum STEPMODE
{
    step_single_step,
    step_emu_all,
    step_stop_ret,
    step_max
};

bool InitEmuEngine();
bool SetupEnvironment(uc_engine* eng);
bool SetupDescriptorTable(uc_engine* eng);
bool SetupContext(uc_engine* eng);
bool PrepareDataToEmulate(void* data, size_t dataLen, duint start_addr, bool curCip);
