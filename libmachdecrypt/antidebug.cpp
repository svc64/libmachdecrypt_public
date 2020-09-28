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
    mib[3] = getpid();

    sysctl(mib, sizeof(mib) / sizeof(*mib), &info, &size, NULL, 0);

    return (info.kp_proc.p_flag & P_TRACED) != 0;
}
