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
#include "antidebug.hpp"
#include "key.h"
extern void notmain() __asm__("main");
void mymemcpy(void *dest, void *src, size_t n);
static void integrityChecker();
static void antiDebug();
static void cryptText();
bool textDecrypted = false;
uint32_t cryptKey;
void mymemcpy(void *dest, void *src, size_t n)
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
        /*
         unsigned int
              sleep(unsigned int)
         */
        unsigned int (*sleep)(unsigned int) = (unsigned int (*)(unsigned int))dlsym(RTLD_NEXT, "sleep");
        sleep(5);
        antiDebug();
        if(antidebug::AmIBeingDebugged()) {
            // If we're being debugged, encrypt __text again to avoid someone dumping code
            if(textDecrypted) {
                cryptText();
                // int     system(const char *)
                int (*system)(const char *) = (int (*)(const char *))dlsym(RTLD_NEXT, "system");
                system("killall -9 lldb gdb iTerm Terminal");
            }
        }
    }
}
int mymemcmp (const void * str1, const void * str2, size_t count)
{
  const unsigned char *s1 = (const unsigned char*)str1;
  const unsigned char *s2 = (const unsigned char*)str2;

  while (count-- > 0)
    {
      if (*s1++ != *s2++)
      return s1[-1] < s2[-1] ? -1 : 1;
    }
  return 0;
}
int mystrcmp(char string1[], char string2[] )
{
    for (int i = 0; ; i++)
    {
        if (string1[i] != string2[i])
        {
            return string1[i] < string2[i] ? -1 : 1;
        }

        if (string1[i] == '\0')
        {
            return 0;
        }
    }
}
static void antiDebug() {
#if DEBUG
    printf("hi from antidebug\n");
    return;
#endif
    uint8_t denyAttach[] = { 0x50, 0x57, 0xBF, 0x1F, 0x00, 0x00, 0x00, 0xB8, 0x1A, 0x00, 0x00, 0x02, 0x0F, 0x05, 0x5F, 0x58 , 0xC3}; // calls ptrace
    /*
     kern_return_t vm_protect
     (
         vm_map_t target_task,
         vm_address_t address,
         vm_size_t size,
         boolean_t set_maximum,
         vm_prot_t new_protection
     );
     */
    int (*vm_protect)(vm_map_t target_task, vm_address_t address, vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection) = (int (*)(vm_map_t target_task, vm_address_t address, vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection))dlsym(RTLD_NEXT, "vm_protect");
    
    vm_protect(mach_task_self(), (mach_vm_address_t)(notmain), sizeof(denyAttach), false, VM_PROT_ALL);
    mymemcpy((void*)notmain, &denyAttach, sizeof(denyAttach));
    notmain();
}
__attribute__((constructor))
static void start()
{
#if !DEBUG
    /*
     FILE    *freopen(const char * __restrict, const char * __restrict,
                      FILE * __restrict)
     */
    FILE* (*freopen)(const char * __restrict, const char * __restrict, FILE * __restrict) = (FILE* (*)(const char * __restrict, const char * __restrict, FILE * __restrict))dlsym(RTLD_NEXT, "freopen");
    freopen("/dev/null", "w", stdout);
#endif
    antiDebug();
    int temp;
    pthread_t tid;
    pthread_attr_t attr;
    // int pthread_attr_init(pthread_attr_t *);
    int (*pthread_attr_init)(pthread_attr_t *) = (int (*)(pthread_attr_t *))dlsym(RTLD_NEXT, "pthread_attr_init");
    pthread_attr_init(&attr);
    int (*pthread_create)(pthread_t _Nullable * _Nonnull __restrict, const pthread_attr_t * _Nullable __restrict, void * _Nullable (* _Nonnull)(void * _Nullable), void * _Nullable __restrict) = (int (*)(pthread_t _Nullable * _Nonnull __restrict, const pthread_attr_t * _Nullable __restrict, void * _Nullable (* _Nonnull)(void * _Nullable), void * _Nullable __restrict))(dlsym(RTLD_NEXT, "pthread_create"));
        
    pthread_create(&tid, &attr, integrityChecker, (void*)&temp);
    // int     unsetenv(const char *)
    int (*unsetenv)(const char *) = (int (*)(const char *))dlsym(RTLD_NEXT, "unsetenv");
    unsetenv("DYLD_INSERT_LIBRARIES");
#if DEBUG
    printf("we run\n");
#endif
    cryptText();
}
static void cryptText() {
    mymemcpy(&cryptKey, key, sizeof(uint32_t));
    //extern intptr_t                    _dyld_get_image_vmaddr_slide(uint32_t image_index)
    intptr_t (*_dyld_get_image_vmaddr_slide)(uint32_t image_index) = (intptr_t (*)(uint32_t image_index))dlsym(RTLD_NEXT, "_dyld_get_image_vmaddr_slide");
    void * macho = (void*)(_dyld_get_image_vmaddr_slide(0)+0x100000000);
    int32_t magic = MH_MAGIC_64;
    if(mymemcmp(macho, &magic, sizeof(MH_MAGIC_64))==0) {
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
                if(mystrcmp(segCommand->segname, "__TEXT")==0) {
#if DEBUG
                    printf("found __TEXT, starts at 0x%llx with VM address 0x%llx\n" , segCommand->fileoff, segCommand->vmaddr);
#endif
                    // find the __text section
                    struct section_64 * sections = (struct section_64 *)((uint64_t)segCommand+sizeof(struct segment_command_64));
                    for(int i=0;i<segCommand->nsects;i++) {
#if DEBUG
                        printf("%s\n", sections[i].sectname);
#endif
                        if(mystrcmp(sections[i].sectname, "__text")==0) {
#if DEBUG
                            printf("found the __text section, starts at 0x%x, size 0x%llx\n", sections[i].offset, sections[i].size);
#endif
                            int (*vm_protect)(vm_map_t target_task, vm_address_t address, vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection) = (int (*)(vm_map_t target_task, vm_address_t address, vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection))dlsym(RTLD_NEXT, "vm_protect");
                            int err = vm_protect(mach_task_self(), (mach_vm_address_t)((uint64_t)macho+sections[i].offset), (vm_size_t)sections[i].size, false, VM_PROT_ALL);
#if DEBUG
                            if(err) {
                                printf("%s\n", mach_error_string(err));
                                abort();
                            }
#endif
#if DEBUG
                            printf("your key: 0x%x\n", cryptKey);
#endif
                            // "encrypt" the text section
                            for(uint32_t x=sections[i].offset;x<sections[i].offset+sections[i].size;x+=sizeof(uint32_t)) {
#if DEBUG
                                if(x+sizeof(uint32_t)-sections[i].offset>sections[i].size) { // bounds test
                                    printf("we're at the end!");
                                }
#endif
                                uint32_t toEncrypt;
                                mymemcpy(&toEncrypt, (void *)(x+(uint64_t)macho), sizeof(uint32_t));
                                if(textDecrypted) {
                                    toEncrypt = toEncrypt-cryptKey;
                                } else {
                                    toEncrypt = toEncrypt+cryptKey;
                                }
                                mymemcpy((void *)(x+(uint64_t)macho), &toEncrypt, sizeof(uint32_t));
                            }
#if DEBUG
                            goto end;
#endif
                            if(textDecrypted==false) {
                                textDecrypted=true;
                            } else {
                                textDecrypted=false;
                            }
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
