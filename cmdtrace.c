
#include <sys/ptrace.h>
#include <bits/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <string.h>

enum argtype {
    ARG_INT,
    ARG_PTR,
    ARG_STR
} argtypes[] = { ARG_STR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR };
/* cheap trick for reading syscall number / return value. */
#ifdef __amd64__
#define eax rax
#define orig_eax orig_rax
#else
#endif

#define offsetof(a, b) __builtin_offsetof(a,b)
#define get_reg(child, name) __get_reg(child, offsetof(struct user, regs.name))

long __get_reg(pid_t child, int off) {
    long val = ptrace(PTRACE_PEEKUSER, child, off);
    assert(errno == 0);
    return val;
}

int wait_for_syscall(pid_t child) {
    int status;
    while (1) {
        ptrace(PTRACE_SYSCALL, child, 0, 0);
        waitpid(child, &status, 0);
        if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80)
            return 0;
        if (WIFEXITED(status))
            return 1;
		if (status>>8 == (SIGTRAP | (PTRACE_EVENT_EXEC<<8)))
			fprintf(stderr, "EXEC %d %d %d\n", status, child, getpid());
		if (status>>8 == (SIGTRAP | (PTRACE_EVENT_FORK<<8)))
			fprintf(stderr, "FORK %d %d %d\n", status, child, getpid());
		if (status>>8 == (SIGTRAP | (PTRACE_EVENT_VFORK<<8)))
			fprintf(stderr, "VFORK %d %d %d\n", status, child, getpid());
		if (status>>8 == (SIGTRAP | (PTRACE_EVENT_CLONE<<8)))
			fprintf(stderr, "CLONE %d %d %d\n", status, child, getpid());

        fprintf(stderr, "[stopped %d (%x)]\n", status, WSTOPSIG(status));
    }
}

long get_syscall_arg(pid_t child, int which) {
    switch (which) {
#ifdef __amd64__
    case 0: return get_reg(child, rdi);
    case 1: return get_reg(child, rsi);
    case 2: return get_reg(child, rdx);
    case 3: return get_reg(child, r10);
    case 4: return get_reg(child, r8);
    case 5: return get_reg(child, r9);
#else
    case 0: return get_reg(child, ebx);
    case 1: return get_reg(child, ecx);
    case 2: return get_reg(child, edx);
    case 3: return get_reg(child, esi);
    case 4: return get_reg(child, edi);
    case 5: return get_reg(child, ebp);
#endif
    default: return -1L;
    }
}

char *read_string(pid_t child, unsigned long addr) {
    char *val = malloc(4096);
    int allocated = 4096;
    int read = 0;
    unsigned long tmp;
    while (1) {
        if (read + sizeof tmp > allocated) {
            allocated *= 2;
            val = realloc(val, allocated);
        }
        tmp = ptrace(PTRACE_PEEKDATA, child, addr + read);
        if(errno != 0) {
            val[read] = 0;
            break;
        }
        memcpy(val + read, &tmp, sizeof tmp);
        if (memchr(&tmp, 0, sizeof tmp) != NULL)
            break;
        read += sizeof tmp;
    }
    return val;
}


void print_syscall_args(pid_t child, char *strbuf) {
    int i, j;
    char *strval;

    for (i = 0; i < 6; i++) {
        long arg = get_syscall_arg(child, i);
        int type = argtypes[i]; //ARG_PTR;
/*
		if (i==1) {
			for (j = 0; j < sizeof(arg); j++) {
				fprintf(stderr, "LEN %s", arg[j]);
			}
		}
*/
        switch (type) {
        case ARG_INT:
            sprintf(strbuf, "%ld", arg);
            break;
        case ARG_STR:
            strval = read_string(child, arg);
            sprintf(&(strbuf[strlen(strbuf)]), "\"%s\"", strval);
            free(strval);
            break;
        default:
            sprintf(&(strbuf[strlen(strbuf)]), "0x%lx", arg);
            break;
        }
        if (i != 6 - 1)
            sprintf(&(strbuf[strlen(strbuf)]), "%s", ", ");
    }
}

void print_syscall(pid_t child, char *strbuf) {
    int num;
    num = get_reg(child, orig_eax);
    assert(errno == 0);

	if (num == 59) {
		sprintf(strbuf, "%s", "execve(");
		print_syscall_args(child, &(strbuf[7]));
		sprintf(&(strbuf[strlen(strbuf)]), "%s", ") = ");
	} else if (num == 57 || num == 58) {
		fprintf(stderr, "BB");
	}
}

int do_trace(pid_t child) {
    int status;
    int retval;
    char strbuf[2048];
    waitpid(child, &status, 0);
    assert(WIFSTOPPED(status));
    ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC);
    //ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE);
    //ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC);
    //ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD);
    while(1) {

		strbuf[0] = 0;

        if (wait_for_syscall(child) != 0)
            break;

        print_syscall(child, strbuf);

        if (wait_for_syscall(child) != 0)
            break;

        retval = get_reg(child, eax);
        assert(errno == 0);

		if (retval == 0 && strlen(strbuf) > 0) {
			fprintf(stderr, "%s%d\n", strbuf, retval);
		}
    }
    return 0;
}

int do_child(int argc, char **argv) {
    char *args [argc+1];
    int i;
    for (i=0;i<argc;i++)
        args[i] = argv[i];
    args[argc] = NULL;

    ptrace(PTRACE_TRACEME);
    kill(getpid(), SIGSTOP);
	fprintf(stderr, "AA %d\n", getpid());
    return execvp(args[0], args);
}

int main(int argc, char **argv) {
    pid_t child;

    if (argc < 2) {
        //fprintf(stderr, "Usage: %s [-s <syscall int>|-n <syscall name>] <program> <args>\n", argv[0]);
        fprintf(stderr, "Usage: %s <program> <args>\n", argv[0]);
        exit(1);
    }
//
    child = fork();
    if (child == 0) {
        return do_child(argc-1, argv+1);
    } else {
        return do_trace(child);
    }
}
