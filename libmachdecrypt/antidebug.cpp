//
//  antidebug.cpp
//  encryptor
//
//  Created by svc64 on 9/28/20.
//

#include "antidebug.hpp"
#include <assert.h>
#include <stdbool.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <dlfcn.h>

bool antidebug::AmIBeingDebugged(void) {
#if DEBUG
    printf("hello from AmIBeingDebugged\n");
    return false;
#endif
    int mib[4];
    struct kinfo_proc info;
    size_t size = sizeof(info);

    info.kp_proc.p_flag = 0;

    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_PID;
    // pid_t     getpid(void);
    pid_t (*getpid)(void) = (pid_t (*)(void))dlsym(RTLD_NEXT, "getpid");
    mib[3] = getpid();
    // int     sysctl(int *, u_int, void *, size_t *, void *, size_t);
    int (*sysctl)(int *, u_int, void *, size_t *, void *, size_t) = (int (*)(int *, u_int, void *, size_t *, void *, size_t))dlsym(RTLD_NEXT, "sysctl");
    sysctl(mib, sizeof(mib) / sizeof(*mib), &info, &size, NULL, 0);

    return (info.kp_proc.p_flag & P_TRACED) != 0;
}
