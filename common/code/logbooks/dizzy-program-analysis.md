# dizzy-program-analysis

fzf-run.sh - asm check for stdin reads

https://cs.nyu.edu/courses/fall03/V22.0201-003/c_att_syntax.html
    source followed by destination
```bash
objdump -d ~/opt/static-binaries/binaries/linux/x86_64/ncat | awk '/syscall/{print "b *0x" substr($1,1,length($1)-1) " if $rax == 0"}' > ~/123gdb
nc -l -p 8123
gdb ~/opt/static-binaries/binaries/linux/x86_64/ncat
```
```
(gdb) source ~/123gdb
(gdb) run localhost 8123 < ~/123
Breakpoint 142, 0x00000000005d9179 in ?? ()
```
objdump -d ~/opt/static-binaries/binaries/linux/x86_64/ncat
```
5d5ae3:	31 c0                	xor    %eax,%eax
5d5ae5:	e9 78 36 00 00       	jmpq   0x5d9162
[...]
5d9162:	48 89 f8             	mov    %rdi,%rax
5d9165:	48 89 f7             	mov    %rsi,%rdi
5d9168:	48 89 d6             	mov    %rdx,%rsi
5d916b:	48 89 ca             	mov    %rcx,%rdx
5d916e:	4d 89 c2             	mov    %r8,%r10
5d9171:	4d 89 c8             	mov    %r9,%r8
5d9174:	4c 8b 4c 24 08       	mov    0x8(%rsp),%r9
5d9179:	0f 05                	syscall 
```
objdump -T /lib64/libc.so.6
```
00000000000f2530 g    DF .text	000000000000009d  GLIBC_2.2.5 __read
[...]
00000000000f2530 g    DF .text	000000000000009d  GLIBC_2.2.5 read
```
objdump -d /lib64/libc.so.6
```
00000000000f2530 <__read>:
   f2530:	f3 0f 1e fa          	endbr64 
   f2534:	64 8b 04 25 18 00 00 	mov    %fs:0x18,%eax
   f253b:	00 
   f253c:	85 c0                	test   %eax,%eax
   f253e:	75 10                	jne    f2550 <__read+0x20>
   f2540:	0f 05                	syscall 
   f2542:	48 3d 00 f0 ff ff    	cmp    $0xfffffffffffff000,%rax
   f2548:	77 56                	ja     f25a0 <__read+0x70>
   f254a:	c3                   	retq   
   f254b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
   f2550:	48 83 ec 28          	sub    $0x28,%rsp
   f2554:	48 89 54 24 18       	mov    %rdx,0x18(%rsp)
   f2559:	48 89 74 24 10       	mov    %rsi,0x10(%rsp)
   f255e:	89 7c 24 08          	mov    %edi,0x8(%rsp)
   f2562:	e8 69 4b f9 ff       	callq  870d0 <__libc_enable_asynccancel>
   f2567:	48 8b 54 24 18       	mov    0x18(%rsp),%rdx
   f256c:	48 8b 74 24 10       	mov    0x10(%rsp),%rsi
   f2571:	41 89 c0             	mov    %eax,%r8d
   f2574:	8b 7c 24 08          	mov    0x8(%rsp),%edi
   f2578:	31 c0                	xor    %eax,%eax
   f257a:	0f 05                	syscall 
```
https://stackoverflow.com/questions/25972841/how-can-i-set-breakpoint-in-gdb-for-open2-syscall-returning-1
    Here you can see that the stub behaves differently depending on whether the program has multiple threads or not. This has to do with asynchronous cancellation.
    https://chromium.googlesource.com/chromiumos/third_party/glibc/+/cvs/fedora-glibc-2_3_3-75/linuxthreads/libc-cancellation.c#37
https://filippo.io/linux-syscall-table/
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/read_write.c
```c
SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)
{
	return ksys_read(fd, buf, count);
}
// [...]
ssize_t ksys_read(unsigned int fd, char __user *buf, size_t count)
{
	struct fd f = fdget_pos(fd);
	ssize_t ret = -EBADF;

	if (f.file) {
		loff_t pos, *ppos = file_ppos(f.file);
		if (ppos) {
			pos = *ppos;
			ppos = &pos;
		}
		ret = vfs_read(f.file, buf, count, ppos);
		if (ret >= 0 && ppos)
			f.file->f_pos = pos;
		fdput_pos(f);
	}
	return ret;
}
```
https://stackoverflow.com/questions/48418813/gdb-how-to-set-watchpoint-from-file-offset
https://stackoverflow.com/questions/10483544/stopping-at-the-first-machine-code-instruction-in-gdb
gdb /usr/bin/ncat
```
(gdb) b *0
(gdb) run localhost 8123 < ~/123
(gdb) x/i $pc
=> 0x7ffff7fd2110 <_start>:     mov    %rsp,%rdi
(gdb) info proc map
    Start Addr           End Addr       Size     Offset objfile                                                                   
0x555555554000     0x55555555d000     0x9000        0x0 /usr/bin/ncat                 
0x55555555d000     0x5555555a5000    0x48000     0x9000 /usr/bin/ncat                 
0x5555555a5000     0x5555555bf000    0x1a000    0x51000 /usr/bin/ncat                 
0x5555555c0000     0x5555555c2000     0x2000    0x6b000 /usr/bin/ncat                 
0x5555555c2000     0x5555555c3000     0x1000    0x6d000 /usr/bin/ncat
```
objdump -T
```
00000000000f2530 g    DF .text	000000000000009d  GLIBC_2.2.5 __read
00000000000f2530 g    DF .text	000000000000009d  GLIBC_2.2.5 read
```
readelf -Wl /usr/bin/ncat | grep LOAD
```
LOAD           0x000000 0x0000000000000000 0x0000000000000000 0x0082e8 0x0082e8 R   0x1000
LOAD           0x009000 0x0000000000009000 0x0000000000009000 0x047ce5 0x047ce5 R E 0x1000
LOAD           0x051000 0x0000000000051000 0x0000000000051000 0x0199e8 0x0199e8 R   0x1000
LOAD           0x06b250 0x000000000006c250 0x000000000006c250 0x002590 0x003958 RW  0x1000
```
|| readelf -Wl /usr/bin/ncat | awk '/LOAD.* E/{print $2}'
=> section with `E` flag set
```bash
objdump -d /usr/bin/ncat | awk '/callq.*<read@plt>/{print "b *0x55555555d000-0x9000+0x" substr($1,1,length($1)-1) " if $rax == 0"}' > ~/123gdb2
```
gdb /usr/bin/ncat -x ~/123gdb2
```
Breakpoint 1 at 0x5555555655c5
Breakpoint 2 at 0x555555565a29
Breakpoint 3 at 0x555555565c4c
Breakpoint 4 at 0x55555556f388
Breakpoint 5 at 0x55555557208b
Breakpoint 6 at 0x55555557d8ba
(gdb) run localhost 8123 < ~/123
```
none are hit...
=>
```
(gdb) b read@plt
Breakpoint 7 at 0xad70
(gdb) run localhost 8123 < ~/123
Starting program: /usr/bin/ncat localhost 8123 < ~/123
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib64/libthread_db.so.1".

Breakpoint 7, 0x000055555555ed70 in read@plt ()
(gdb) bt
#0  0x000055555555ed70 in read@plt ()
#1  0x000055555557d8bf in nrand_init ()
#2  0x000055555557db14 in get_random_bytes ()
#3  0x0000555555575eb3 in nsock_pool_ssl_init_helper ()
#4  0x00005555555638cd in ncat_connect ()
#5  0x000055555555fdd9 in main ()
(gdb) x/3i 0x000055555555ed70
=> 0x55555555ed70 <read@plt>:   endbr64
   0x55555555ed74 <read@plt+4>: bnd jmpq *0x62fc5(%rip)        # 0x5555555c1d40 <read@got.plt>
   0x55555555ed7b <read@plt+11>:        nopl   0x0(%rax,%rax,1)
```
objdump
```
000000000000ad70 <read@plt>:
    ad70:	f3 0f 1e fa          	endbr64 
    ad74:	f2 ff 25 c5 2f 06 00 	bnd jmpq *0x62fc5(%rip)        # 6dd40 <read@GLIBC_2.2.5>
    ad7b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
```
info proc map
```
    Start Addr           End Addr       Size     Offset objfile
0x555555554000     0x55555555d000     0x9000        0x0 /usr/bin/ncat
```
[T]
we are stopping on the call, but rax = 0 inside the call, so stop at next instruction
=>
```
objdump -d /usr/bin/ncat | awk '/callq.*<read@plt>/{print "b *0x55555555d000-0x9000+0x5+0x" substr($1,1,length($1)-1) " if $rax == 0"}' > ~/123gdb2
```
oh, rax is probably restored at this point, so just skip the condition
=>
```
objdump -d /usr/bin/ncat | awk '/callq.*<read@plt>/{print "b *0x55555555d000-0x9000+0x" substr($1,1,length($1)-1)}' > ~/123gdb2
```
gdb
```
Breakpoint 6, 0x000055555557d8ba in nrand_init ()
=> 0x000055555557d8ba <nrand_init+138>: e8 b1 14 fe ff  callq  0x55555555ed70 <read@plt>
(gdb) c
Continuing.

Breakpoint 5, 0x000055555557208b in do_actual_read ()
=> 0x000055555557208b <do_actual_read+811>:     e8 e0 cc fe ff  callq  0x55555555ed70 <read@plt>
```
objdump
```
   2987a:	e8 b1 0e fe ff       	callq  a730 <open@plt>
   2987f:	41 89 c5             	mov    %eax,%r13d
   29882:	83 f8 ff             	cmp    $0xffffffff,%eax
   29885:	0f 84 c6 01 00 00    	je     29a51 <X509_gmtime_adj@plt+0x1e7d1>
   2988b:	e8 10 09 fe ff       	callq  a1a0 <__errno_location@plt>
   29890:	4c 8d 74 24 14       	lea    0x14(%rsp),%r14
   29895:	49 89 c4             	mov    %rax,%r12
   29898:	eb 0d                	jmp    298a7 <X509_gmtime_adj@plt+0x1e627>
   2989a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
   298a0:	41 83 3c 24 04       	cmpl   $0x4,(%r12)
   298a5:	75 1d                	jne    298c4 <X509_gmtime_adj@plt+0x1e644>
   298a7:	41 c7 04 24 00 00 00 	movl   $0x0,(%r12)
   298ae:	00 
   298af:	ba ec 00 00 00       	mov    $0xec,%edx
   298b4:	4c 89 f6             	mov    %r14,%rsi
   298b7:	44 89 ef             	mov    %r13d,%edi
   298ba:	e8 b1 14 fe ff       	callq  ad70 <read@plt>
   [...]
   1de11:	e8 9a cd fe ff       	callq  abb0 <SSL_read@plt>
   [...]
   1e06c:	0f 1f 40 00          	nopl   0x0(%rax)
   1e070:	31 f6                	xor    %esi,%esi
   1e072:	c7 44 24 2c 00 00 00 	movl   $0x0,0x2c(%rsp)
   1e079:	00 
   1e07a:	ba 00 20 00 00       	mov    $0x2000,%edx
   1e07f:	66 89 74 24 30       	mov    %si,0x30(%rsp)
   1e084:	41 8b 3c 24          	mov    (%r12),%edi
   1e088:	48 89 de             	mov    %rbx,%rsi
   1e08b:	e8 e0 cc fe ff       	callq  ad70 <read@plt>
```
https://stackoverflow.com/questions/14267081/difference-between-je-jne-and-jz-jnz
https://stackoverflow.com/questions/147173/testl-eax-against-eax
https://stackoverflow.com/questions/17030771/why-does-x86-nopl-instruction-take-an-operand
https://stackoverflow.com/questions/26058665/fs-register-in-assembly-code
https://stackoverflow.com/questions/23220206/what-are-pthread-cancelation-points-used-for
https://stackoverflow.com/questions/12806584/what-is-better-int-0x80-or-syscall-in-32-bit-code-on-linux

[ ] reach all syscalls - coverage-based fuzzing + symbolic execution
https://github.com/nahueldsanchez/UnicornPlayground
https://github.com/fireeye/flare-emu

https://stackoverflow.com/questions/5748492/is-there-any-api-for-determining-the-physical-address-from-virtual-address-in-li/45128487#45128487
