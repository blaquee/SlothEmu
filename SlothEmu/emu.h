#pragma once

#include "plugin.h"
#include "unicorn/unicorn.h"
#include "capstone_wrapper/capstone_wrapper.h"
#include "Cpu.h"

#include <vector>


/* EXTERNS defined and initialized elsewhere */
extern bool isDebugging;
extern uc_hook hookcode;
extern uc_hook hookMemInvalid;
extern uc_hook hookMem;
/*********************************************/


// Some structs
typedef struct _DSTADDRINFO
{
	duint from;
	duint to;
	bool toMainMod; //is this in the main module?
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

typedef struct _STACKINFO
{
	duint tid;
	duint base;
	duint limit;
}STACKINFO, *PSTACKINFO;

// Work on this later
/*
namespace engine
{
	class EmuEngine
	{
	private:
		uc_engine* eng;
		bool mEngineInit;
		bool mStackInit;
		bool mGdtInit;
		bool mFsSegInit;
		bool mGsSegInit;
		//bool mLightEmu;

		char* mInstructionData;
		std::vector<unsigned char> data;
		// disassembled instructions with info
		std::vector<Capstone> cInstructions;


	public:
		EmuEngine::EmuEngine():
		mEngineInit(false),
		mStackInit(false),
		mGdtInit(false),
		mFsSegInit(false),
		mGsSegInit(false),
		mInstructionData(nullptr),
		eng(nullptr)
		{
		}

		~EmuEngine();

		Capstone GetInstruction(unsigned int index);
		bool AccessDescriptors();
		bool EngineInit();
		bool AccessSegments();
		bool AddDataToEmulate(unsigned char* data, size_t len, duint start_address);
		bool CopyDataToEmulate(const unsigned char* data);

		//callbacks

	};

}
*/

#define CHECKED_WRITE_REG(err, uc, reg, value)	\
if (!(uc))return false;							\
err = uc_reg_write((uc), (reg), (value));		\
if (err != UC_ERR_OK) return false;



bool InitEmuEngine();
bool PrepareDataToEmulate(const unsigned char* data, size_t dataLen, duint start_addr, bool curCip);

void EmuGetStackInfoForThread(duint threadId, STACKINFO* sinfo);
void EmuGetCurrentStackLimit(duint & limit);
void EmuGetCurrentStackBase(duint & base);

bool EmuSetupRegs(uc_engine* uc, Cpu* cpu);
bool EmulateData(uc_engine* uc, const unsigned char* data, size_t len, duint start, bool zeroRegs);
void CleanupEmuEngine();