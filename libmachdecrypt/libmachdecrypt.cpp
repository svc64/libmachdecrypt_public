//
//  libmachdecrypt.cpp
//  libmachdecrypt
//
//  Created by svc64 on 9/27/20.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mach-o/loader.h>
#include <mach-o/dyld.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/task.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <assert.h>
#include <pthread.h>
extern void notmain() __asm__("main");
void myMemCpy(void *dest, void *src, size_t n);
static void integrityChecker();
static void antiDebug();

void myMemCpy(void *dest, void *src, size_t n)
{
   // Typecast src and dest addresses to (char *)
   char *csrc = (char *)src;
   char *cdest = (char *)dest;
  
   // Copy contents of src[] to dest[]
   for (int i=0; i<n; i++)
       cdest[i] = csrc[i];
}

// TODO integrity checker
static void *integrityChecker(void* data) {
    while(&free) {
        sleep(5);
        antiDebug();
    }
}
static void antiDebug() {
#if DEBUG
    printf("hi from antidebug\n");
    return;
#endif
    uint8_t denyAttach[] = { 0x50, 0x57, 0xBF, 0x1F, 0x00, 0x00, 0x00, 0xB8, 0x1A, 0x00, 0x00, 0x02, 0x0F, 0x05, 0x5F, 0x58 , 0xC3};
    int err = vm_protect(mach_task_self(), (mach_vm_address_t)(notmain), sizeof(denyAttach), false, VM_PROT_ALL);
#if DEBUG
    if(err) {
        printf("%s\n", mach_error_string(err));
        abort();
    }
#endif
    myMemCpy((void*)notmain, &denyAttach, sizeof(denyAttach));
    notmain();
}
__attribute__((constructor))
static void start()
{
    antiDebug();
    int temp;
    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    int (*pthread_create)(pthread_t _Nullable * _Nonnull __restrict,
                           const pthread_attr_t * _Nullable __restrict,
                           void * _Nullable (* _Nonnull)(void * _Nullable),
                           void * _Nullable __restrict) = (int (*)(pthread_t  _Nullable * _Nonnull, const pthread_attr_t * _Nullable, void * _Nullable (* _Nonnull)(void * _Nullable), void * _Nullable))(dlsym(RTLD_NEXT, "pthread_create"));
    pthread_create(&tid, &attr, integrityChecker, (void*)&temp);
    
    unsetenv("DYLD_INSERT_LIBRARIES");
#if DEBUG
    printf("we run\n");
#endif
    void * macho = (void*)(_dyld_get_image_vmaddr_slide(0)+0x100000000);
    int32_t magic = MH_MAGIC_64;
    if(memcmp(macho, &magic, sizeof(MH_MAGIC_64))==0) {
#if DEBUG
        printf("supported mach-o!\n");
#endif
        
        struct mach_header_64 * header = (mach_header_64 *)macho;
        
#if DEBUG
        printf("load commands: %d size: %d\n", header->ncmds, header->sizeofcmds);
#endif
        
        void * loadCommands = (void*)((uint64_t)macho+sizeof(mach_header_64));
        
#if DEBUG
        printf("load commands offset: 0x%llx\n", (uint64_t)loadCommands-(uint64_t)macho);
#endif
        // find __TEXT
        uint64_t currentOffset = 0; // the offset of the current load command we're looking at
        while(currentOffset<header->sizeofcmds) {
            struct load_command * loadCommand = (struct load_command *)((uint64_t)loadCommands+currentOffset);
            // we only care about LC_SEGMENT_64
            if(loadCommand->cmd==LC_SEGMENT_64) {
                struct segment_command_64 * segCommand = (struct segment_command_64 *)((uint64_t)loadCommands+currentOffset);
                if(strcmp(segCommand->segname, "__TEXT")==0) {
#if DEBUG
                    printf("found __TEXT, starts at 0x%llx with VM address 0x%llx\n" , segCommand->fileoff, segCommand->vmaddr);
#endif
                    // find the __text section
                    struct section_64 * sections = (struct section_64 *)((uint64_t)segCommand+sizeof(struct segment_command_64));
                    for(int i=0;i<segCommand->nsects;i++) {
#if DEBUG
                        printf("%s\n", sections[i].sectname);
#endif
                        if(strcmp(sections[i].sectname, "__text")==0) {
#if DEBUG
                            printf("found the __text section, starts at 0x%x, size 0x%llx\n", sections[i].offset, sections[i].size);
#endif
                            int err = vm_protect(mach_task_self(), (mach_vm_address_t)((uint64_t)macho+sections[i].offset), (vm_size_t)sections[i].size, false, VM_PROT_ALL);
#if DEBUG
                            if(err) {
                                printf("%s\n", mach_error_string(err));
                                abort();
                            }
#endif
                            uint32_t key = 0xc9a7c7d1;
#if DEBUG
                            printf("your key: 0x%x\n", key);
#endif
                            // XOR the text section
                            for(uint32_t x=sections[i].offset;x<sections[i].offset+sections[i].size;x+=sizeof(uint32_t)) {
#if DEBUG
                                if(x+sizeof(uint32_t)-sections[i].offset>sections[i].size) { // bounds test
                                    printf("we're at the end!");
                                }
#endif
                                uint32_t toEncrypt;
                                myMemCpy(&toEncrypt, (void *)(x+(uint64_t)macho), sizeof(uint32_t));
                                toEncrypt = toEncrypt^key;
                                myMemCpy((void *)(x+(uint64_t)macho), &toEncrypt, sizeof(uint32_t));
                                
                            }
#if DEBUG
                            goto end;
#endif
                            return;
                        }
                    }
                }
            }
            currentOffset+=loadCommand->cmdsize;
        }
    }
#if DEBUG
    end:
    printf("yolo\n");
#endif
}
