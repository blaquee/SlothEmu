#pragma once

#include <windows.h>

// borrowed from pegasus project
#define CF_INDEX	0
#define PF_INDEX	2
#define AF_INDEX	4
#define ZF_INDEX	6
#define SF_INDEX	7
#define TF_INDEX	8
#define IF_INDEX	9
#define DF_INDEX	10
#define OF_INDEX	11
#define IOPL_INDEX_1	12
#define IOPL_INDEX_2	13
#define NT_INDEX		14
#define RF_INDEX		16
#define VM_INDEX		17
#define AC_INDEX		18
#define VIF_INDEX		19
#define VIP_INDEX		20
#define ID_INDEX		21


#pragma pack(push, 1)
typedef struct _SegmentDescriptor {
    union {
        struct {
            unsigned short limit_low;
            unsigned short base_low;
            unsigned char base_mid;
            unsigned char type : 4;
            unsigned char system : 1;
            unsigned char dpl : 2;
            unsigned char present : 1;
            unsigned char limit_hi : 4;
            unsigned char available : 1;
            unsigned char is_64_code : 1;
            unsigned char db : 1;
            unsigned char granularity : 1;
            unsigned char base_hi;
        };
        unsigned long long descriptor; // resize 8byte.
    };
}SegmentDescriptor, *PSegmentDescriptor;
#pragma pack(pop)


// borrowed from rewolf
#pragma pack(push)
#pragma pack(1)
template <class T>
struct LIST_ENTRY_T
{
    T Flink;
    T Blink;
};

template <class T>
struct UNICODE_STRING_T
{
    union
    {
        struct
        {
            WORD Length;
            WORD MaximumLength;
        };
        T dummy;
    };
    T _Buffer;
};

template <class T, class NGF, int A>
struct _PEB_T
{
    union
    {
        struct
        {
            BYTE InheritedAddressSpace;
            BYTE ReadImageFileExecOptions;
            BYTE BeingDebugged;
            BYTE _SYSTEM_DEPENDENT_01;
        };
        T dummy01;
    };
    T Mutant;
    T ImageBaseAddress;
    T Ldr;
    T ProcessParameters;
    T SubSystemData;
    T ProcessHeap;
    T FastPebLock;
    T _SYSTEM_DEPENDENT_02;
    T _SYSTEM_DEPENDENT_03;
    T _SYSTEM_DEPENDENT_04;
    union
    {
        T KernelCallbackTable;
        T UserSharedInfoPtr;
    };
    DWORD SystemReserved;
    DWORD _SYSTEM_DEPENDENT_05;
    T _SYSTEM_DEPENDENT_06;
    T TlsExpansionCounter;
    T TlsBitmap;
    DWORD TlsBitmapBits[2];
    T ReadOnlySharedMemoryBase;
    T _SYSTEM_DEPENDENT_07;
    T ReadOnlyStaticServerData;
    T AnsiCodePageData;
    T OemCodePageData;
    T UnicodeCaseTableData;
    DWORD NumberOfProcessors;
    union
    {
        DWORD NtGlobalFlag;
        NGF dummy02;
    };
    LARGE_INTEGER CriticalSectionTimeout;
    T HeapSegmentReserve;
    T HeapSegmentCommit;
    T HeapDeCommitTotalFreeThreshold;
    T HeapDeCommitFreeBlockThreshold;
    DWORD NumberOfHeaps;
    DWORD MaximumNumberOfHeaps;
    T ProcessHeaps;
    T GdiSharedHandleTable;
    T ProcessStarterHelper;
    T GdiDCAttributeList;
    T LoaderLock;
    DWORD OSMajorVersion;
    DWORD OSMinorVersion;
    WORD OSBuildNumber;
    WORD OSCSDVersion;
    DWORD OSPlatformId;
    DWORD ImageSubsystem;
    DWORD ImageSubsystemMajorVersion;
    T ImageSubsystemMinorVersion;
    union
    {
        T ImageProcessAffinityMask;
        T ActiveProcessAffinityMask;
    };
    T GdiHandleBuffer[A];
    T PostProcessInitRoutine;
    T TlsExpansionBitmap;
    DWORD TlsExpansionBitmapBits[32];
    T SessionId;
    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    T pShimData;
    T AppCompatInfo;
    UNICODE_STRING_T<T> CSDVersion;
    T ActivationContextData;
    T ProcessAssemblyStorageMap;
    T SystemDefaultActivationContextData;
    T SystemAssemblyStorageMap;
    T MinimumStackCommit;
};

typedef _PEB_T<DWORD, DWORD64, 34> PEB32;
typedef _PEB_T<DWORD64, DWORD, 30> PEB64;
#pragma pack(pop)

