#pragma once
#define WIN32_NO_STATUS
#include <stdio.h>
#include <stdint.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <psapi.h>
#include <winternl.h>
#include <winioctl.h>
#include <stddef.h>
#pragma comment(lib,"ws2_32.lib") //Winsock Library
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#pragma warning(disable:4996)
#define FSCTL_PIPE_INTERNAL_WRITE 0x119FF8
#define IRP_INPUT_OPERATION   0x00000040
#define IRP_BUFFERED_IO   0x00000010
#define IRP_DEALLOCATE_BUFFER   0x00000020
#define EPROCESS_OFFSET 0x318
#define PID_OFFSET 0x440
#define ACTIVELINKS_OFFSET 0x448
#define EPROCESS_TOKEN_OFFSET 0x4b8
#define OBJECT_TABLE_OFFSET 0x570
typedef void (IO_APC_ROUTINE)(
    void* ApcContext,
    IO_STATUS_BLOCK* IoStatusBlock,
    unsigned long    reserved
    );
typedef int(__stdcall* NTFSCONTROLFILE)(
    HANDLE           fileHandle,
    HANDLE           event,
    IO_APC_ROUTINE* apcRoutine,
    void* ApcContext,
    IO_STATUS_BLOCK* ioStatusBlock,
    unsigned long    FsControlCode,
    void* InputBuffer,
    unsigned long    InputBufferLength,
    void* OutputBuffer,
    unsigned long    OutputBufferLength
    );

typedef enum _NP_DATA_QUEUE_ENTRY_TYPE
{
    Buffered = 0x0,
    Unbuffered = 0x1,
}NP_DATA_QUEUE_ENTRY_TYPE;

typedef enum _NP_DATA_QUEUE_STATE
{
    ReadEntries = 0x0,
    WriteEntries = 0x1,
    Empty = 0x2,
}NP_DATA_QUEUE_STATE;

typedef struct {
    USHORT Type;
    USHORT Size;
    USHORT AllocationProcessorNumber;
    USHORT Reserved;
    PVOID64 MdlAddress;
    ULONG64 Flags;
    PVOID64 AssociatedIrp;
    LIST_ENTRY64 ThreadListEntry;
    ULONG64 IoStatus[2];
    CHAR RequestorMode;
    BOOLEAN PendingReturned;
    CHAR StackCount;
    CHAR CurrentLocation;
    BOOLEAN Cancel;
    UCHAR CancelIrql;
    CCHAR ApcEnvironment;
    UCHAR AllocationFlags;
    PVOID64 UserIosb;
    PVOID64 UserEvent;
    char Overlay[16];
    PVOID64 CancelRoutine;
    PVOID64 UserBuffer;
    char Tail[0x58];
} IRP;

typedef struct {
    uint64_t Flink;
    uint64_t Blink;
    uint64_t Irp;
    uint64_t SecurityContext;
    uint32_t EntryType;
    uint32_t QuotaInEntry;
    uint32_t DataSize;
    uint32_t x;
} DATA_QUEUE_ENTRY;
typedef struct _NP_DATA_QUEUE
{
    LIST_ENTRY64 Queue;
    NP_DATA_QUEUE_STATE QueueState;
    uint32_t BytesInQueue;
    uint32_t EntriesInQueue;
    uint32_t quota;
    uint32_t QuotaUsed;
    uint32_t ByteOffset;
}NP_DATA_QUEUE;

typedef struct _SECURITY_CLIENT_CONTEXT
{
    SECURITY_QUALITY_OF_SERVICE SecurityQos;
    PACCESS_TOKEN ClientToken;
    BOOLEAN DirectlyAccessClientToken;
    BOOLEAN DirectAccessEffectiveOnly;
    BOOLEAN ServerIsRemote;
    TOKEN_CONTROL ClientTokenControl;
}SECURITY_CLIENT_CONTEXT, * PSECURITY_CLIENT_CONTEXT;

