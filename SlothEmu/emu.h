#pragma once

#include "unicorn/unicorn.h"
#include "capstone_wrapper/capstone_wrapper.h"
#include "defines.h"
#include "plugin.h"
#include <vector>


// Some structs
typedef struct _DSTADDRINFO
{
	duint addr;
	bool inMod; //is this in the main module?
}DSTADDRINFO, *PDSTADDRINFO;

typedef struct _MEMACCESSINFO
{
	duint addr;
	size_t size;
	bool mapped;

}MEMACCESSINFO, *PMEMACCESSINFO;

typedef struct
{
	duint addr;
	duint modBase;
}MODCALLINFO;

typedef struct  
{
	unsigned char* data;
	size_t len;
	std::vector<MODCALLINFO> modCalls;
	std::vector<DSTADDRINFO> dstInfo;

}EMUDATA;

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
		//bool mLightEmu;

		std::vector<unsigned char> data;
		std::vector<Capstone> cInstructions;


	public:
		EmuEngine::EmuEngine():
		mEngineInit(false),
		mStackInit(false),
		mGdtInit(false),
		mFsSegInit(false),
		mGsSegInit(false)
		{
		}

		~EmuEngine();

		Capstone GetInstruction(unsigned int index);
		bool AccessDescriptors();
		bool EngineInit();
		bool AccessSegments();
		bool AddDataToEmulate(unsigned char* data, size_t len);


	};

}



bool InitEmuEngine();
bool SetupEnvironment(uc_engine* eng, duint threadID);
bool SetupDescriptorTable(uc_engine* eng);
bool SetupContext(uc_engine* eng);
bool PrepareDataToEmulate(const unsigned char* data, size_t dataLen, duint start_addr, bool curCip);

bool EmulateData(uc_engine* eng, unsigned char* data, size_t len);
void CleanupEmuEngine();