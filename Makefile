CC := gcc

cmdtrace: cmdtrace.c
	${CC} -o $@ $^

strace:
	strace -o strace.log -f -q -s 100000 -e trace=execve  -- /bin/sh -c "${CMD}"

clean:
	rm -f cmdtrace strace.log
