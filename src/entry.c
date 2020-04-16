#include "elf_abi.h"
#include "sd_loader.h"
#include "../sd_loader/src/common.h"
#include <stdint.h>
#include <string.h>

#define OSDynLoad_Acquire ((void (*)(char* rpl, unsigned int *handle))0x0102A3B4)
#define OSDynLoad_FindExport ((void (*)(unsigned int handle, int isdata, char *symbol, void *address))0x0102B828)
#define OSFatal ((void (*)(char* msg))0x01031618)

#define EXPORT_DECL(res, func, ...) res (* func)(__VA_ARGS__);
#define OS_FIND_EXPORT(handle, funcName, func) OSDynLoad_FindExport(handle, 0, funcName, &func)

#define ADDRESS_OSTitle_main_entry_ptr              0x1005E040
#define ADDRESS_main_entry_hook                     0x0101c56c

#define KERN_SYSCALL_TBL_1                          0xFFE84C70 // unknown
#define KERN_SYSCALL_TBL_2                          0xFFE85070 // works with games
#define KERN_SYSCALL_TBL_3                          0xFFE85470 // works with loader
#define KERN_SYSCALL_TBL_4                          0xFFEAAA60 // works with home menu
#define KERN_SYSCALL_TBL_5                          0xFFEAAE60 // works with browser (previously KERN_SYSCALL_TBL)

#define address_LiWaitIopComplete                   0x01010180
#define address_LiWaitIopCompleteWithInterrupts     0x0101006C
#define address_LiWaitOneChunk                      0x0100080C
#define address_PrepareTitle_hook                   0xFFF184E4
#define address_sgIsLoadingBuffer                   0xEFE19E80
#define address_gDynloadInitialized                 0xEFE13DBC

/* assembly functions */
extern void Syscall_0x36(void);
extern void KernelPatches(void);
extern void SCKernelCopyData(unsigned int addr, unsigned int src, unsigned int len);

extern void SC_0x25_KernelCopyData(unsigned int addr, unsigned int src, unsigned int len);

typedef struct
{
    float x,y;
} Vec2D;

typedef struct
{
    uint16_t x, y;               /* Touch coordinates */
    uint16_t touched;            /* 1 = Touched, 0 = Not touched */
    uint16_t invalid;            /* 0 = All valid, 1 = X invalid, 2 = Y invalid, 3 = Both invalid? */
} VPADTPData;

typedef struct
{
    uint32_t btns_h;                  /* Held buttons */
    uint32_t btns_d;                  /* Buttons that are pressed at that instant */
    uint32_t btns_r;                  /* Released buttons */
    Vec2D lstick, rstick;        /* Each contains 4-byte X and Y components */
    char unknown1c[0x52 - 0x1c]; /* Contains accelerometer and gyroscope data somewhere */
    VPADTPData tpdata;           /* Normal touchscreen data */
    VPADTPData tpdata1;          /* Modified touchscreen data 1 */
    VPADTPData tpdata2;          /* Modified touchscreen data 2 */
    char unknown6a[0xa0 - 0x6a];
    uint8_t volume;
    uint8_t battery;             /* 0 to 6 */
    uint8_t unk_volume;          /* One less than volume */
    char unknowna4[0xac - 0xa4];
} VPADData;

void __attribute__ ((noinline)) kern_write(void *addr, uint32_t value);

typedef struct _private_data_t {
    EXPORT_DECL(void *, MEMAllocFromDefaultHeapEx,int size, int align);
    EXPORT_DECL(void, MEMFreeToDefaultHeap,void *ptr);

    EXPORT_DECL(void*, memcpy, void *p1, const void *p2, unsigned int s);
    EXPORT_DECL(void*, memset, void *p1, int val, unsigned int s);

    EXPORT_DECL(unsigned int, OSEffectiveToPhysical, const void*);
    EXPORT_DECL(void, exit, int);
    EXPORT_DECL(void, DCInvalidateRange, const void *addr, unsigned int length);
    EXPORT_DECL(void, DCFlushRange, const void *addr, unsigned int length);
    EXPORT_DECL(void, ICInvalidateRange, const void *addr, unsigned int length);

    EXPORT_DECL(int, FSInit, void);
    EXPORT_DECL(int, FSAddClientEx, void *pClient, int unk_zero_param, int errHandling);
    EXPORT_DECL(int, FSDelClient, void *pClient);
    EXPORT_DECL(void, FSInitCmdBlock, void *pCmd);
    EXPORT_DECL(int, FSGetMountSource, void *pClient, void *pCmd, int type, void *source, int errHandling);
    EXPORT_DECL(int, FSMount, void *pClient, void *pCmd, void *source, const char *target, uint32_t bytes, int errHandling);
    EXPORT_DECL(int, FSUnmount, void *pClient, void *pCmd, const char *target, int errHandling);
    EXPORT_DECL(int, FSOpenFile, void *pClient, void *pCmd, const char *path, const char *mode, int *fd, int errHandling);
    EXPORT_DECL(int, FSGetStatFile, void *pClient, void *pCmd, int fd, void *buffer, int error);
    EXPORT_DECL(int, FSReadFile, void *pClient, void *pCmd, void *buffer, int size, int count, int fd, int flag, int errHandling);
    EXPORT_DECL(int, FSCloseFile, void *pClient, void *pCmd, int fd, int errHandling);

    EXPORT_DECL(int, VPADRead, int controller, VPADData *buffer, unsigned int num, int *error);

    EXPORT_DECL(int, SYSRelaunchTitle, int argc, char** argv);
} private_data_t;

static void InstallPatches(private_data_t *private_data);


static void loadFunctionPointers(private_data_t * private_data) {
    unsigned int coreinit_handle;

    OSDynLoad_Acquire("coreinit", &coreinit_handle);

    unsigned int *functionPtr = 0;

    OSDynLoad_FindExport(coreinit_handle, 1, "MEMAllocFromDefaultHeapEx", &functionPtr);
    private_data->MEMAllocFromDefaultHeapEx = (void * (*)(int, int))*functionPtr;
    OSDynLoad_FindExport(coreinit_handle, 1, "MEMFreeToDefaultHeap", &functionPtr);
    private_data->MEMFreeToDefaultHeap = (void (*)(void *))*functionPtr;

    OS_FIND_EXPORT(coreinit_handle, "memcpy", private_data->memcpy);
    OS_FIND_EXPORT(coreinit_handle, "memset", private_data->memset);
    OS_FIND_EXPORT(coreinit_handle, "DCFlushRange", private_data->DCFlushRange);
    OS_FIND_EXPORT(coreinit_handle, "DCInvalidateRange", private_data->DCInvalidateRange);
    OS_FIND_EXPORT(coreinit_handle, "ICInvalidateRange", private_data->ICInvalidateRange);
    OS_FIND_EXPORT(coreinit_handle, "OSEffectiveToPhysical", private_data->OSEffectiveToPhysical);
    OS_FIND_EXPORT(coreinit_handle, "exit", private_data->exit);

    OS_FIND_EXPORT(coreinit_handle, "FSInit", private_data->FSInit);
    OS_FIND_EXPORT(coreinit_handle, "FSAddClientEx", private_data->FSAddClientEx);
    OS_FIND_EXPORT(coreinit_handle, "FSDelClient", private_data->FSDelClient);
    OS_FIND_EXPORT(coreinit_handle, "FSInitCmdBlock", private_data->FSInitCmdBlock);
    OS_FIND_EXPORT(coreinit_handle, "FSGetMountSource", private_data->FSGetMountSource);
    OS_FIND_EXPORT(coreinit_handle, "FSMount", private_data->FSMount);
    OS_FIND_EXPORT(coreinit_handle, "FSUnmount", private_data->FSUnmount);
    OS_FIND_EXPORT(coreinit_handle, "FSOpenFile", private_data->FSOpenFile);
    OS_FIND_EXPORT(coreinit_handle, "FSGetStatFile", private_data->FSGetStatFile);
    OS_FIND_EXPORT(coreinit_handle, "FSReadFile", private_data->FSReadFile);
    OS_FIND_EXPORT(coreinit_handle, "FSCloseFile", private_data->FSCloseFile);

    unsigned int vpad_handle;
    OSDynLoad_Acquire("vpad.rpl", &vpad_handle);
    OS_FIND_EXPORT(vpad_handle, "VPADRead", private_data->VPADRead);

    unsigned int sysapp_handle;
    OSDynLoad_Acquire("sysapp.rpl", &sysapp_handle);
    OS_FIND_EXPORT(sysapp_handle, "SYSRelaunchTitle", private_data->SYSRelaunchTitle);
}

static unsigned int load_elf_image (private_data_t *private_data, unsigned char *elfstart) {
    Elf32_Ehdr *ehdr;
    Elf32_Phdr *phdrs;
    unsigned char *image;
    int i;

    ehdr = (Elf32_Ehdr *) elfstart;

    if(ehdr->e_phoff == 0 || ehdr->e_phnum == 0)
        return 0;

    if(ehdr->e_phentsize != sizeof(Elf32_Phdr))
        return 0;

    phdrs = (Elf32_Phdr*)(elfstart + ehdr->e_phoff);

    for(i = 0; i < ehdr->e_phnum; i++) {
        if(phdrs[i].p_type != PT_LOAD)
            continue;

        if(phdrs[i].p_filesz > phdrs[i].p_memsz)
            continue;

        if(!phdrs[i].p_filesz)
            continue;

        unsigned int p_paddr = phdrs[i].p_paddr;
        image = (unsigned char *) (elfstart + phdrs[i].p_offset);

        private_data->memcpy ((void *) p_paddr, image, phdrs[i].p_filesz);
        private_data->DCFlushRange((void*)p_paddr, phdrs[i].p_filesz);

        if(phdrs[i].p_flags & PF_X)
            private_data->ICInvalidateRange ((void *) p_paddr, phdrs[i].p_memsz);
    }

    //! clear BSS
    Elf32_Shdr *shdr = (Elf32_Shdr *) (elfstart + ehdr->e_shoff);
    for(i = 0; i < ehdr->e_shnum; i++) {
        const char *section_name = ((const char*)elfstart) + shdr[ehdr->e_shstrndx].sh_offset + shdr[i].sh_name;
        if(section_name[0] == '.' && section_name[1] == 'b' && section_name[2] == 's' && section_name[3] == 's') {
            private_data->memset((void*)shdr[i].sh_addr, 0, shdr[i].sh_size);
            private_data->DCFlushRange((void*)shdr[i].sh_addr, shdr[i].sh_size);
        } else if(section_name[0] == '.' && section_name[1] == 's' && section_name[2] == 'b' && section_name[3] == 's' && section_name[4] == 's') {
            private_data->memset((void*)shdr[i].sh_addr, 0, shdr[i].sh_size);
            private_data->DCFlushRange((void*)shdr[i].sh_addr, shdr[i].sh_size);
        }
    }

    return ehdr->e_entry;
}


void KernelWriteU32(uint32_t addr, uint32_t value, private_data_t * pdata) {
    pdata->ICInvalidateRange(&value, 4);
    pdata->DCFlushRange(&value, 4);

    uint32_t dst = (uint32_t) pdata->OSEffectiveToPhysical((void *)addr);
    uint32_t src = (uint32_t) pdata->OSEffectiveToPhysical((void *)&value);

    SC_0x25_KernelCopyData(dst, src, 4);

    pdata->DCFlushRange((void *)addr, 4);
    pdata->ICInvalidateRange((void *)addr, 4);
}

#define BUTTON_A        0x8000
#define BUTTON_B        0x4000
#define BUTTON_X        0x2000
#define BUTTON_Y        0x1000
#define BUTTON_LEFT     0x0800
#define BUTTON_RIGHT    0x0400
#define BUTTON_UP       0x0200
#define BUTTON_DOWN     0x0100
#define BUTTON_ZL       0x0080
#define BUTTON_ZR       0x0040
#define BUTTON_L        0x0020
#define BUTTON_R        0x0010
#define BUTTON_PLUS     0x0008
#define BUTTON_MINUS    0x0004
#define BUTTON_HOME     0x0002
#define BUTTON_SYNC     0x0001

typedef struct
{
	int val;
	char txt[12];
} config_select;

static const config_select sel[17] = {
	{BUTTON_A,"a="},
	{BUTTON_B,"b="},
	{BUTTON_X,"x="},
	{BUTTON_Y,"y="},
	{BUTTON_LEFT,"left="},
	{BUTTON_RIGHT,"right="},
	{BUTTON_UP,"up="},
	{BUTTON_DOWN,"down="},
	{BUTTON_ZL,"zl="},
	{BUTTON_ZR,"zr="},
	{BUTTON_L,"l="},
	{BUTTON_R,"r="},
	{BUTTON_PLUS,"plus="},
	{BUTTON_MINUS,"minus="},
	{BUTTON_HOME,"home="},
	{BUTTON_SYNC,"sync="},
	{0,"default="},
};

typedef struct
{
    uint32_t flag;
    uint32_t permission;
    uint32_t owner_id;
    uint32_t group_id;
    uint32_t size;
    uint32_t alloc_size;
    uint64_t quota_size;
    uint32_t ent_id;
    uint64_t ctime;
    uint64_t mtime;
    uint8_t attributes[48];
} __attribute__((packed)) FSStat;

#define __os_snprintf ((int(*)(char* s, int n, const char * format, ... ))0x0102F160)
#define MIN(a, b) (((a)>(b))?(b):(a))

int _start(int argc, char **argv) {
    kern_write((void*)(KERN_SYSCALL_TBL_1 + (0x25 * 4)), (unsigned int)SCKernelCopyData);
    kern_write((void*)(KERN_SYSCALL_TBL_2 + (0x25 * 4)), (unsigned int)SCKernelCopyData);
    kern_write((void*)(KERN_SYSCALL_TBL_3 + (0x25 * 4)), (unsigned int)SCKernelCopyData);
    kern_write((void*)(KERN_SYSCALL_TBL_4 + (0x25 * 4)), (unsigned int)SCKernelCopyData);
    kern_write((void*)(KERN_SYSCALL_TBL_5 + (0x25 * 4)), (unsigned int)SCKernelCopyData);

    kern_write((void*)(KERN_SYSCALL_TBL_1 + (0x36 * 4)), (unsigned int)KernelPatches);
    kern_write((void*)(KERN_SYSCALL_TBL_2 + (0x36 * 4)), (unsigned int)KernelPatches);
    kern_write((void*)(KERN_SYSCALL_TBL_3 + (0x36 * 4)), (unsigned int)KernelPatches);
    kern_write((void*)(KERN_SYSCALL_TBL_4 + (0x36 * 4)), (unsigned int)KernelPatches);
    kern_write((void*)(KERN_SYSCALL_TBL_5 + (0x36 * 4)), (unsigned int)KernelPatches);

    Syscall_0x36();

    private_data_t private_data;
    loadFunctionPointers(&private_data);

	//default path goes to HBL
	strcpy((void*)0xF5E70000,"/vol/external01/wiiu/apps/homebrew_launcher/homebrew_launcher.elf");

    int iFd = -1;
	void *pClient = private_data.MEMAllocFromDefaultHeapEx(0x1700,4);
	void *pCmd = private_data.MEMAllocFromDefaultHeapEx(0xA80,4);
	void *pBuffer = NULL;

    private_data.FSInit();
	private_data.FSInitCmdBlock(pCmd);
	private_data.FSAddClientEx(pClient, 0, -1);

    char tempPath[0x300];
    char mountPath[128];

    // mount sd
    private_data.FSGetMountSource(pClient, pCmd, 0, tempPath, -1);
    private_data.FSMount(pClient, pCmd, tempPath, mountPath, 128, -1);

	private_data.FSOpenFile(pClient, pCmd, CAFE_OS_SD_PATH WIIU_PATH "/payload.cfg", "r", &iFd, -1);
	if(iFd < 0)
		goto fileEnd;

	FSStat stat;
	stat.size = 0;

	private_data.FSGetStatFile(pClient, pCmd, iFd, &stat, -1);

	if(stat.size > 0)
	{
		pBuffer = private_data.MEMAllocFromDefaultHeapEx(stat.size+1, 0x40);
		private_data.memset(pBuffer, 0, stat.size + 1);
	}
	else
		goto fileEnd;

	unsigned int done = 0;

	while(done < stat.size)
	{
		int readBytes = private_data.FSReadFile(pClient, pCmd, pBuffer + done, 1, stat.size - done, iFd, 0, -1);
		if(readBytes <= 0) {
			break;
		}
		done += readBytes;
	}

	char *fList = (char*)pBuffer;

	int error;
	VPADData vpad_data;
	private_data.VPADRead(0, &vpad_data, 1, &error);
	char FnameChar[256];
	private_data.memset(FnameChar, 0, 256);
	int i;
	for(i = 0; i < 17; i++)
	{
		if((vpad_data.btns_h & sel[i].val) || (sel[i].val == 0))
		{
			char *n = strstr(fList,sel[i].txt);
			if(n)
			{
				char *fEnd = NULL;
				char *fName = n  + strlen(sel[i].txt);
				char *fEndR = strchr(fName, '\r');
				char *fEndN = strchr(fName, '\n');
				if(fEndR)
				{
					if(fEndN && fEndN < fEndR)
						fEnd = fEndN;
					else
						fEnd = fEndR;
				}
				else if(fEndN)
				{
					if(fEndR && fEndR < fEndN)
						fEnd = fEndR;
					else
						fEnd = fEndN;
				}
				else
					fEnd = fName + strlen(fName);
				if(fEnd && fName < fEnd)
				{
					int fLen = MIN(fEnd-fName, 255);
					private_data.memcpy(FnameChar, fName, fLen);
                    if(memcmp(FnameChar + fLen -  4, ".elf", 5) == 0)
					{
						if(FnameChar[0] == '/')
							__os_snprintf((void*)0xF5E70000, 250, CAFE_OS_SD_PATH "%s", FnameChar);
						else
							__os_snprintf((void*)0xF5E70000, 250, CAFE_OS_SD_PATH "/%s", FnameChar);
						break;
					}
				}
			}
		}
	}
fileEnd:
    if(pClient && pCmd)
	{
		if(iFd >= 0)
			private_data.FSCloseFile(pClient, pCmd, iFd, -1);
        private_data.FSUnmount(pClient, pCmd, mountPath, -1);
		private_data.FSDelClient(pClient);
		private_data.MEMFreeToDefaultHeap(pClient);
		private_data.MEMFreeToDefaultHeap(pCmd);
	}
	if(pBuffer)
		private_data.MEMFreeToDefaultHeap(pBuffer);

    InstallPatches(&private_data);

    unsigned char * pElfBuffer = (unsigned char *) sd_loader_sd_loader_elf; // use this address as temporary to load the elf

    unsigned int mainEntryPoint = load_elf_image(&private_data, pElfBuffer);

    if(mainEntryPoint == 0) {
        OSFatal("failed to load elf");
    }

    //! Install our entry point hook
    unsigned int repl_addr = ADDRESS_main_entry_hook;
    unsigned int jump_addr = mainEntryPoint & 0x03fffffc;

    unsigned int bufferU32 = 0x48000003 | jump_addr;
    KernelWriteU32(repl_addr,bufferU32,&private_data);

    // restart mii maker.
    private_data.SYSRelaunchTitle(0, 0);
    private_data.exit(0);
    return 0;

    //return ((int (*)(int, char **))mainEntryPoint)(argc, argv);
}

/* Write a 32-bit word with kernel permissions */
void __attribute__ ((noinline)) kern_write(void *addr, uint32_t value) {
    asm volatile (
        "li 3,1\n"
        "li 4,0\n"
        "mr 5,%1\n"
        "li 6,0\n"
        "li 7,0\n"
        "lis 8,1\n"
        "mr 9,%0\n"
        "mr %1,1\n"
        "li 0,0x3500\n"
        "sc\n"
        "nop\n"
        "mr 1,%1\n"
        :
        :	"r"(addr), "r"(value)
        :	"memory", "ctr", "lr", "0", "3", "4", "5", "6", "7", "8", "9", "10",
        "11", "12"
    );
}

/* ****************************************************************** */
/*                         INSTALL PATCHES                            */
/* All OS specific stuff is done here                                 */
/* ****************************************************************** */
static void InstallPatches(private_data_t *private_data) {
    OsSpecifics osSpecificFunctions;
    private_data->memset(&osSpecificFunctions, 0, sizeof(OsSpecifics));

    unsigned int bufferU32;
    /* Pre-setup a few options to defined values */
    bufferU32 = 550;
    private_data->memcpy((void*)&OS_FIRMWARE, &bufferU32, sizeof(bufferU32));
    bufferU32 = 0xDEADC0DE;
    private_data->memcpy((void*)&MAIN_ENTRY_ADDR, &bufferU32, sizeof(bufferU32));
    private_data->memcpy((void*)&ELF_DATA_ADDR, &bufferU32, sizeof(bufferU32));
    bufferU32 = 0;
    private_data->memcpy((void*)&ELF_DATA_SIZE, &bufferU32, sizeof(bufferU32));

	private_data->memcpy((void*)SD_LOADER_PATH, (void*)0xF5E70000, 250);

    osSpecificFunctions.addr_OSDynLoad_Acquire = (unsigned int)OSDynLoad_Acquire;
    osSpecificFunctions.addr_OSDynLoad_FindExport = (unsigned int)OSDynLoad_FindExport;

    osSpecificFunctions.addr_KernSyscallTbl1 = KERN_SYSCALL_TBL_1;
    osSpecificFunctions.addr_KernSyscallTbl2 = KERN_SYSCALL_TBL_2;
    osSpecificFunctions.addr_KernSyscallTbl3 = KERN_SYSCALL_TBL_3;
    osSpecificFunctions.addr_KernSyscallTbl4 = KERN_SYSCALL_TBL_4;
    osSpecificFunctions.addr_KernSyscallTbl5 = KERN_SYSCALL_TBL_5;

    osSpecificFunctions.LiWaitIopComplete = (int (*)(int, int *)) address_LiWaitIopComplete;
    osSpecificFunctions.LiWaitIopCompleteWithInterrupts = (int (*)(int, int *)) address_LiWaitIopCompleteWithInterrupts;
    osSpecificFunctions.addr_LiWaitOneChunk = address_LiWaitOneChunk;
    osSpecificFunctions.addr_PrepareTitle_hook = address_PrepareTitle_hook;
    osSpecificFunctions.addr_sgIsLoadingBuffer = address_sgIsLoadingBuffer;
    osSpecificFunctions.addr_gDynloadInitialized = address_gDynloadInitialized;
    osSpecificFunctions.orig_LiWaitOneChunkInstr = *(unsigned int*)address_LiWaitOneChunk;

    //! pointer to main entry point of a title
    osSpecificFunctions.addr_OSTitle_main_entry = ADDRESS_OSTitle_main_entry_ptr;

    private_data->memcpy((void*)OS_SPECIFICS, &osSpecificFunctions, sizeof(OsSpecifics));
}
