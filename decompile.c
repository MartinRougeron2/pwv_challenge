#include "out.h"
#include <types.h>

void _DT_INIT(void)

{
    __gmon_start__();
    return;
}

void FUN_00100c20(void)

{
    // WARNING: Treating indirect jump as call
    (*(code *)(undefined *)0x0)();
    return;
}

void free(void *__ptr)

{
    free(__ptr);
    return;
}

void setspent(void)

{
    setspent();
    return;
}

void endspent(void)

{
    endspent();
    return;
}

// WARNING: Unknown calling convention -- yet parameter storage is locked

int *__errno_location(void)

{
    int *piVar1;

    piVar1 = __errno_location();
    return piVar1;
}

// WARNING: Unknown calling convention -- yet parameter storage is locked

char *strncpy(char *__dest, char *__src, size_t __n)

{
    char *pcVar1;

    pcVar1 = strncpy(__dest, __src, __n);
    return pcVar1;
}

// WARNING: Unknown calling convention -- yet parameter storage is locked

ssize_t mq_timedreceive(mqd_t __mqdes, char *__msg_ptr, size_t __msg_len, uint *__msg_prio,
                        timespec *__abs_timeout)

{
    ssize_t sVar1;

    sVar1 = mq_timedreceive(__mqdes, __msg_ptr, __msg_len, __msg_prio, __abs_timeout);
    return sVar1;
}

void lckpwdf(void)

{
    lckpwdf();
    return;
}

// WARNING: Unknown calling convention -- yet parameter storage is locked

int mq_unlink(char *__name)

{
    int iVar1;

    iVar1 = mq_unlink(__name);
    return iVar1;
}

// WARNING: Unknown calling convention -- yet parameter storage is locked

mqd_t mq_open(char *__name, int __oflag, ...)

{
    mqd_t mVar1;

    mVar1 = mq_open(__name, __oflag);
    return mVar1;
}

void __stack_chk_fail(void)

{
    // WARNING: Subroutine does not return
    __stack_chk_fail();
}

// WARNING: Unknown calling convention -- yet parameter storage is locked

int snprintf(char *__s, size_t __maxlen, char *__format, ...)

{
    int iVar1;

    iVar1 = snprintf(__s, __maxlen, __format);
    return iVar1;
}

// WARNING: Unknown calling convention -- yet parameter storage is locked

__uid_t geteuid(void)

{
    __uid_t _Var1;

    _Var1 = geteuid();
    return _Var1;
}

// WARNING: Unknown calling convention -- yet parameter storage is locked

char *crypt(char *__key, char *__salt)

{
    char *pcVar1;

    pcVar1 = crypt(__key, __salt);
    return pcVar1;
}

// WARNING: Unknown calling convention -- yet parameter storage is locked

int strcmp(char *__s1, char *__s2)

{
    int iVar1;

    iVar1 = strcmp(__s1, __s2);
    return iVar1;
}

// WARNING: Unknown calling convention -- yet parameter storage is locked

__sighandler_t signal(int __sig, __sighandler_t __handler)

{
    __sighandler_t p_Var1;

    p_Var1 = signal(__sig, __handler);
    return p_Var1;
}

// WARNING: Unknown calling convention -- yet parameter storage is locked

int fprintf(FILE *__stream, char *__format, ...)

{
    int iVar1;

    iVar1 = fprintf(__stream, __format);
    return iVar1;
}

// WARNING: Unknown calling convention -- yet parameter storage is locked

time_t time(time_t *__timer)

{
    time_t tVar1;

    tVar1 = time(__timer);
    return tVar1;
}

// WARNING: Unknown calling convention -- yet parameter storage is locked

ssize_t mq_receive(mqd_t __mqdes, char *__msg_ptr, size_t __msg_len, uint *__msg_prio)

{
    ssize_t sVar1;

    sVar1 = mq_receive(__mqdes, __msg_ptr, __msg_len, __msg_prio);
    return sVar1;
}

void getspent(void)

{
    getspent();
    return;
}

// WARNING: Unknown calling convention -- yet parameter storage is locked

void *malloc(size_t __size)

{
    void *pvVar1;

    pvVar1 = malloc(__size);
    return pvVar1;
}

// WARNING: Unknown calling convention -- yet parameter storage is locked

int mq_send(mqd_t __mqdes, char *__msg_ptr, size_t __msg_len, uint __msg_prio)

{
    int iVar1;

    iVar1 = mq_send(__mqdes, __msg_ptr, __msg_len, __msg_prio);
    return iVar1;
}

// WARNING: Unknown calling convention -- yet parameter storage is locked

__pid_t waitpid(__pid_t __pid, int *__stat_loc, int __options)

{
    __pid_t _Var1;

    _Var1 = waitpid(__pid, __stat_loc, __options);
    return _Var1;
}

void ulckpwdf(void)

{
    ulckpwdf();
    return;
}

// WARNING: Unknown calling convention -- yet parameter storage is locked

void perror(char *__s)

{
    perror(__s);
    return;
}

// WARNING: Unknown calling convention -- yet parameter storage is locked

int atoi(char *__nptr)

{
    int iVar1;

    iVar1 = atoi(__nptr);
    return iVar1;
}

// WARNING: Unknown calling convention -- yet parameter storage is locked

void exit(int __status)

{
    // WARNING: Subroutine does not return
    exit(__status);
}

// WARNING: Unknown calling convention -- yet parameter storage is locked

size_t fwrite(void *__ptr, size_t __size, size_t __n, FILE *__s)

{
    size_t sVar1;

    sVar1 = fwrite(__ptr, __size, __n, __s);
    return sVar1;
}

// WARNING: Unknown calling convention -- yet parameter storage is locked

__pid_t fork(void)

{
    __pid_t _Var1;

    _Var1 = fork();
    return _Var1;
}

void __cxa_finalize(void)

{
    __cxa_finalize();
    return;
}

void processEntry entry(int8 param_1, int8 param_2)

{
    undefined auStack_8[8];

    __libc_start_main(main, param_2, &stack0x00000008, FUN_00101a20, FUN_00101a90, param_1,
                      auStack_8);
    do
    {
        // WARNING: Do nothing block with infinite loop
    } while (true);
}

// WARNING: Removing unreachable block (ram,0x00100e47)
// WARNING: Removing unreachable block (ram,0x00100e53)

void null_(void)

{
    return;
}

// WARNING: Removing unreachable block (ram,0x00100e98)
// WARNING: Removing unreachable block (ram,0x00100ea4)

void ull(void)

{
    return;
}

void _FINI_0(void)

{
    if (DAT_00303048 != '\0')
    {
        return;
    }
    __cxa_finalize(PTR_LOOP_00303008);
    null_();
    DAT_00303048 = 1;
    return;
}

void _INIT_0(void)

{
    ull();
    return;
}

void removemsgQ(char *param_1)

{
    mq_unlink(param_1);
    return;
}

void exit_on_signals(void)

{
    fwrite("caught signal, exiting!\n", 1, 0x18, stderr);
    removemsgQ("/pwv-hashes");
    removemsgQ("/pwv-results");
    // WARNING: Subroutine does not return
    exit(1);
}

void exit_on_bad_input(int8 param_1)

{
    fprintf(stderr,
            "usage: %s <num_workers>\nexample: \n%s 2 # starts two worker processes to analyze passwords\n", param_1, param_1);
    // WARNING: Subroutine does not return
    exit(1);
}

mqd_t open_msg_queue(char *param_1)

{
    mqd_t mVar1;
    long in_FS_OFFSET;
    undefined local_58[8];
    int8 local_50;
    int8 local_48;
    long local_10;

    local_10 = *(long *)(in_FS_OFFSET + 0x28);
    local_50 = 4;
    local_48 = 0x421;
    mVar1 = mq_open(param_1, 0xc2, 0x1b6, local_58);
    if (mVar1 == -1)
    {
        fwrite("error: could not create message queue!\n", 1, 0x27, stderr);
        // WARNING: Subroutine does not return
        exit(1);
    }
    if (local_10 != *(long *)(in_FS_OFFSET + 0x28))
    {
        // WARNING: Subroutine does not return
        __stack_chk_fail();
    }
    return mVar1;
}

char *passhashes1(void)

{
    int iVar1;
    int *piVar2;
    char *__dest;
    char **ppcVar3;
    char *local_28;
    char *local_20;

    local_28 = (char *)0x0;
    local_20 = (char *)0x0;
    iVar1 = lckpwdf();
    if (iVar1 != 0)
    {
        piVar2 = __errno_location();
        if (*piVar2 == 0xd)
        {
            fwrite("error: could not obtain shadow file lock. Are you root?\n", 1, 0x38, stderr);
        }
        else
        {
            fwrite("error: could not obtain shadow file lock for 15s. Exiting...\n", 1, 0x3d, stderr);
        }
        // WARNING: Subroutine does not return
        exit(1);
    }
    setspent();
    __dest = local_28;
    do
    {
        do
        {
            local_28 = __dest;
            ppcVar3 = (char **)getspent();
            if (ppcVar3 == (char **)0x0)
            {
            readpasswd:
                endspent();
                ulckpwdf();
                return local_20;
            }
            iVar1 = strcmp(ppcVar3[1], "*");
            __dest = local_28;
        } while (((iVar1 == 0) || (iVar1 = strcmp(ppcVar3[1], "!"), iVar1 == 0)) || (*ppcVar3[1] == '\0'));
        __dest = (char *)malloc(0x430);
        if (__dest == (char *)0x0)
        {
            fwrite("error: could not allocate memory for hash entry, shadow file will not be processed in full!\n", 1, 0x5c, stderr);
            goto readpasswd;
        }
        strncpy(__dest, *ppcVar3, 0x21);
        __dest[0x20] = '\0';
        strncpy(__dest + 0x21, ppcVar3[1], 0x400);
        __dest[0x420] = '\0';
        *(int8 *)(__dest + 0x428) = 0;
        if (local_20 == (char *)0x0)
        {
            local_20 = __dest;
        }
        if (local_28 != (char *)0x0)
        {
            *(char **)(local_28 + 0x428) = __dest;
        }
    } while (true);
}

void chech_if_found(mqd_t param_1)

{
    ssize_t sVar1;
    long in_FS_OFFSET;
    char local_438[33];
    undefined local_417[1031];
    long local_10;

    local_10 = *(long *)(in_FS_OFFSET + 0x28);
    while (true)
    {
        sVar1 = mq_receive(param_1, local_438, 0x421, (uint *)0x0);
        if ((int)sVar1 == -1)
        {
            fwrite("error: could not dequeue message!\n", 1, 0x22, stderr);
            // WARNING: Subroutine does not return
            exit(1);
        }
        if (local_438[0] == '\0')
            break;
        fprintf(stdout, "weak credentials {%s:%s} found\n", local_438, local_417);
    }
    if (local_10 != *(long *)(in_FS_OFFSET + 0x28))
    {
        // WARNING: Subroutine does not return
        __stack_chk_fail();
    }
    return;
}

undefined4 crypt_with_salt(char *param_1, char *param_2)

{
    int iVar1;
    char *__s1;
    undefined4 local_14;

    local_14 = 0;
    __s1 = crypt(param_1, param_2);
    if (__s1 != (char *)0x0)
    {
        iVar1 = strcmp(__s1, param_2);
        if (iVar1 == 0)
        {
            local_14 = 1;
        }
    }
    return local_14;
}

void strncpy_param1_with_2_3(char *param_1, char *param_2, char *param_3)

{
    strncpy(param_1, param_2, 0x21);
    param_1[0x20] = '\0';
    strncpy(param_1 + 0x21, param_3, 0x400);
    param_1[0x420] = '\0';
    return;
}

int8 crypto_ops(long hashed, int8 passwd)
{
    int iVar1;
    int8 uVar2;
    long in_FS_OFFSET;
    char test_str[72];
    long local_10;

    local_10 = *(long *)(in_FS_OFFSET + 0x28);
    iVar1 = crypt_with_salt(hashed, hashed + 0x21);
    if (iVar1 == 0)
    {
        snprintf(test_str, 0x40, "%s1234", hashed);
        iVar1 = crypt_with_salt(test_str, hashed + 0x21);
        if (iVar1 == 0)
        {
            snprintf(test_str, 0x40, "%s!@#$", hashed);
            iVar1 = crypt_with_salt(test_str, hashed + 0x21);
            if (iVar1 == 0)
            {
                uVar2 = 0;
            }
            else
            {
                strncpy_param1_with_2_3(passwd, hashed, test_str);
                uVar2 = 1;
            }
        }
        else
        {
            strncpy_param1_with_2_3(passwd, hashed, test_str);
            uVar2 = 1;
        }
    }
    else
    {
        strncpy_param1_with_2_3(passwd, hashed, hashed);
        uVar2 = 1;
    }
    if (local_10 != *(long *)(in_FS_OFFSET + 0x28))
    {
        // WARNING: Subroutine does not return
        __stack_chk_fail();
    }
    return uVar2;
}

int8 brut_nums(long param_1, int8 param_2)

{
    int iVar1;
    int8 uVar2;
    long in_FS_OFFSET;
    uint local_1c;
    char local_15[5];
    long local_10;

    local_10 = *(long *)(in_FS_OFFSET + 0x28);
    local_1c = 0;
    do
    {
        if (9999 < (int)local_1c)
        {
            uVar2 = 0;
        LAB_0010154d:
            if (local_10 != *(long *)(in_FS_OFFSET + 0x28))
            {
                // WARNING: Subroutine does not return
                __stack_chk_fail();
            }
            return uVar2;
        }
        snprintf(local_15, 5, "%.4d", (ulong)local_1c);
        iVar1 = crypt_with_salt(local_15, param_1 + 0x21);
        if (iVar1 != 0)
        {
            strncpy_param1_with_2_3(param_2, param_1, local_15);
            uVar2 = 1;
            goto LAB_0010154d;
        }
        local_1c = local_1c + 1;
    } while (true);
}

void main_loop(mqd_t param_1, mqd_t param_2)

{
    int iVar1;
    time_t tVar2;
    ssize_t sVar3;
    int *piVar4;
    long in_FS_OFFSET;
    timespec local_878;
    char local_868[1072];
    char local_438[1064];
    long local_10;

    local_10 = *(long *)(in_FS_OFFSET + 0x28);
receive_msg_and_try:
    tVar2 = time((time_t *)0x0);
    local_878.tv_sec = tVar2 + 1;
    local_878.tv_nsec = 0;
    sVar3 = mq_timedreceive(param_1, local_868, 0x421, (uint *)0x0, &local_878);
    if ((int)sVar3 == -1)
    {
        piVar4 = __errno_location();
        if (*piVar4 != 0x6e)
        {
            perror("worker: ");
            fwrite("error: could not dequeue message!\n", 1, 0x22, stderr);
            // WARNING: Subroutine does not return
            exit(1);
        }
        if (local_10 != *(long *)(in_FS_OFFSET + 0x28))
        {
            // WARNING: Subroutine does not return
            __stack_chk_fail();
        }
        return;
    }
    iVar1 = crypto_ops(local_868, local_438);
    if (iVar1 == 0)
        goto try_numbers;
    goto send_msg;
try_numbers:
    iVar1 = brut_nums(local_868, local_438);
    if (iVar1 != 0)
    {
    send_msg:
        mq_send(param_2, local_438, 0x421, 0);
    }
    goto receive_msg_and_try;
}

void wait_for_child_procs(int param_1, undefined4 param_2, undefined4 param_3)

{
    __pid_t _Var1;
    int local_c;

    fwrite("Trying username patterns and 4-digit patterns, please stand by.\n", 1, 0x40, stderr);
    local_c = 0;
    while (true)
    {
        if (param_1 <= local_c)
        {
            for (; 0 < local_c; local_c = local_c + -1)
            {
                waitpid(-1, (int *)0x0, 0);
            }
            return;
        }
        _Var1 = fork();
        if (_Var1 == 0)
            break;
        local_c = local_c + 1;
    }
    main_loop(param_2, param_3);
    // WARNING: Subroutine does not return
    exit(0);
}

void fork_and_do(undefined4 param_1, undefined4 param_2, mqd_t param_3)

{
    __pid_t __pid;
    __pid_t __pid_00;
    long in_FS_OFFSET;
    char local_438[1064];
    long local_10;

    local_10 = *(long *)(in_FS_OFFSET + 0x28);
    __pid = fork();
    if (__pid == 0)
    {
        chech_if_found(param_3);
        // WARNING: Subroutine does not return
        exit(0);
    }
    __pid_00 = fork();
    if (__pid_00 == 0)
    {
        wait_for_child_procs(param_1, param_2, param_3);
        // WARNING: Subroutine does not return
        exit(0);
    }
    waitpid(__pid_00, (int *)0x0, 0);
    local_438[0] = '\0';
    mq_send(param_3, local_438, 0x421, 0);
    waitpid(__pid, (int *)0x0, 0);
    if (local_10 != *(long *)(in_FS_OFFSET + 0x28))
    {
        // WARNING: Subroutine does not return
        __stack_chk_fail();
    }
    return;
}

void FUN_00101824(mqd_t param_1)

{
    char *pcVar1;
    char *local_18;

    local_18 = (char *)passhashes1();
    while (local_18 != (char *)0x0)
    {
        mq_send(param_1, local_18, 0x421, 0);
        pcVar1 = *(char **)(local_18 + 0x428);
        free(local_18);
        local_18 = pcVar1;
    }
    return;
}

int8 main(int param_1, int8 *param_2)

{
    __uid_t _Var1;
    int iVar2;
    undefined4 uVar3;
    undefined4 uVar4;
    __pid_t __pid;
    __pid_t __pid_00;

    if (param_1 != 2)
    {
        exit_on_bad_input(*param_2);
    }
    _Var1 = geteuid();
    if (_Var1 != 0)
    {
        fwrite("this program must run as root\n", 1, 0x1e, stderr);
        // WARNING: Subroutine does not return
        exit(1);
    }
    iVar2 = atoi((char *)param_2[1]);
    if ((iVar2 < 1) || (0x10 < iVar2))
    {
        fwrite("error: number of workers must be between 1 and 16\n", 1, 0x32, stderr);
        // WARNING: Subroutine does not return
        exit(1);
    }
    uVar3 = open_msg_queue("/pwv-hashes");
    uVar4 = open_msg_queue("/pwv-results");
    signal(0xf, exit_on_signals);
    signal(2, exit_on_signals);
    __pid = fork();
    if (__pid == 0)
    {
        FUN_00101824(uVar3);
        // WARNING: Subroutine does not return
        exit(0);
    }
    __pid_00 = fork();
    if (__pid_00 == 0)
    {
        fork_and_do(iVar2, uVar3, uVar4);
        // WARNING: Subroutine does not return
        exit(0);
    }
    waitpid(__pid, (int *)0x0, 0);
    waitpid(__pid_00, (int *)0x0, 0);
    removemsgQ("/pwv-hashes");
    removemsgQ("/pwv-results");
    fwrite("Exiting.\n", 1, 9, stderr);
    return 0;
}

void FUN_00101a20(undefined4 param_1, int8 param_2, int8 param_3)

{
    long lVar1;

    _DT_INIT();
    lVar1 = 0;
    do
    {
        (*(code *)(&__DT_INIT_ARRAY)[lVar1])(param_1, param_2, param_3);
        lVar1 = lVar1 + 1;
    } while (lVar1 != 1);
    return;
}

void FUN_00101a90(void)

{
    return;
}

void _DT_FINI(void)

{
    return;
}
