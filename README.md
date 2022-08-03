# Spock SLAF 
Spock SLAF is a **Shared Library Application Firewall** "SLAF". It has the purpose to protect any service that uses the [OpenSSL library](https://www.openssl.org/docs/man1.1.1/man3/SSL_read.html). The SLAF inserts hooking to intercept all communication to detect security anomalies and block and log attacks like buffer overflow, path traversal, XSS and SQL injection. So to detect anomalies, Spock uses [Deterministic Finite Automaton](https://en.wikipedia.org/wiki/Deterministic_finite_automaton) with rank scores to compute risks and create alerts for each context.

<img align="left" width="280" height="240" src="https://github.com/CoolerVoid/spock_slaf/blob/main/doc/spock_slaf_logo.png">
My beginning purpose in this project is to protect any binary that has communication with TLS using OpenSSL resources. 

Features
---
* Action to Block, log and detect security anomalies like SQL injection, XSS, path traversal from SSL_read() function(get input buffers).
* Capacity to run in any programme that uses the OpenSSL library.
* If detect anomaly in TLS context, Spock saves the IP address of the attacker, date time and attack "payload" register in log file "spock_agressors.log".
* Block SQL injection attack
* Block XSS attack
* Block path traversal attack
* Block remote buffer overflow attack(detect arch of binary and use custom list of shellcodes)
* Block format string attacks

## Video demo

https://www.youtube.com/watch?v=Lm3kpA-NZnE

## Etymology

The motivation for this tool was released during a mitigation project in the past seven years an old. Following my freelancer task, an old client has disclosed a problem around deprecated proprietary binary with many vulnerabilities like Heap buffer overflows, remote buffer overflow and path traversal. The big problem of binary context is the application turn abandonware with no patch fixes, but the enterprise needs to run production loads. So my solution was to insert **[seccomp()](https://kubernetes.io/docs/tutorials/security/seccomp/)** to restrict syscalls in the process(you know, block calls like system()/execv()). I replaced libc's malloc() with **["DieHard", an error-resistant memory allocator](https://github.com/emeryberger/DieHard)**. On the other hand, another initiative was little hooking in OpenSSL's SSL_read() function to restrict some evil payloads, another option.

Another option is to use **[libreSSL](https://www.libressl.org/)** and up a monitor to listen if it has a compatibility bug. The lousy point of LibreSSL is the performance; you can see that if you use a tool like gprof to get a benchmark between OpenSSL and LibreSSL. So OpenSSL is cool but not safest like LibreSSL or lib Sodium. Looking at the performance context, if you get arithmetic functions to big int of OpenSSL, some resources like **[Big int operations BN_new()](https://www.openssl.org/docs/man1.0.2/man3/bn.html)** do not have a good performance like **[libGMP](https://gmplib.org/gmp6.1)**. So relax. Performance is not always the best path for security. Security validations and extra buffer and proper bounds checks have an expected cost, without this, you can see a lot of problems for example looking to **[spectre/meltdown](https://meltdownattack.com/)** in the past.

Following additional facts, external rules of server using **[BSD's firewall](https://www.openbsd.org/faq/pf/filter.html)(aka packet filter)**, using custom rules to **[allow only by IP and OS fingerprint](https://www.openbsd.org/faq/pf/filter.html#osfp)**. So that freelancer task stuck in my mind, now you can see my new solution following a global approach to protect TLS communication in the server context.



The first step compile to deploy
--

Clone the repository:
```
$ git clone https://github.com/CoolerVoid/spock_slaf
```

Enter in the folder:
```
$ cd CoolerVoid/spock_slaf
```
Compile the content:
```
$ make clean; make
```
Now you can see the shared library "spock_slaf.so.1" in "bin" directory.



Second step inject to protect
--

Second step is inject shared library in your binary that uses OpenSSL following communication context(server).

So now we can [use LD_PRELOAD trick:](https://catonmat.net/simple-ld-preload-tutorial)
```
$ LD_PRELOAD=/home/cooler/spock_slaf/bin/spock_slaf.so.1 bin/rest_server
# note: change /home/cooler/spock_slaf/bin/ to your full path name
```
Looking to this example, so has been tested in [simple rest server](https://github.com/CoolerVoid/optionscat).
If anyone attacks the rest_server, you can see the full log in the file "spock_agressors.log".


Extra tips and tricks for customization
--
* You can customize the score rank to detect the anomaly, if set macro **SPOCK_SCORE** to any number between 1 to 10(Low number is more sensitive).
* You can customize the list of attack payloads to block. Please look at the source code.
* You can gain performance in HTTP context, if set macro **SPOCK_ONLY_HTTP to "1"** in the source code.
* You can remove debug mode, if set macro **SPOCK_BUGVIEW to "0"** in the source code.

Understand anti buffer overflow trap
--
So Spock detects shellcode in payloads and blocks attacks of memory corruption, following common chunks in registers for the context of the binary in execution, for example detecting x32 or x64 architecture and blocking specific attacks for architecture.
```c
#if UINTPTR_MAX == 0xffffffffffffffff
	const char *custom_shellcode[] = 
	{
		"\\x48\\x31\\xc0",                    // xor    rax,rax  X64 LINUX
		"\\x48\\x31\\xdb",                    // xor    rbx,rbx  X64 LINUX
	    	"\\x48\\x31\\xff",                    // xor    rdi,rdi  X64 LINUX
	    	"\\x48\\x31\\xf6",                    // xor    rsi,rsi  X64 LINUX
	    	"\\x48\\x31\\xd2",                    // xor    rdx,rdx  X64 LINUX
	    	"\\x48\\x89\\xe6",                    // mov    rsp,rsi  x64 LINUX 
	    	"\\x48\\x89\\xe7"                    // mov    rsp,rdi  x64 LINUX
	};
#elif UINTPTR_MAX == 0xffffffff	
	const char *custom_shellcode[] = 
	{
		"\\x31\\xc0",                         // xor    eax,eax  x32 LINUX
	    	"\\x31\\xc9",                         // xor    ecx,ecx  X32 LINUX
	    	"\\x31\\xdb",                         // xor    ebx,ebx  x32 LINUX
	    	"\\x31\\xd2",                         // xor    edx,edx  X32 LINUX
	    	"\\x89\\xe1",                         // mov    esp,ecx  x32 LINUX
	    	"\\x89\\xe3"                         // mov    esp,ebx  X32 LINUX
	};
#endif
	// ARM, MIPS in the future -- TODO


// generic payloads to block

	const char *list[] = 
	{
		"\\x90\\x90", // block NOP
		"\\x00\\x00", // nullbyte
		"\\xcd\\x80", // int $0x80 
```
So in additional point, Spock uses a custom allocator following anti integer overflow practice of OpenBSD operational system.
```c
// Fork of OpenBSD's function
/*
 * This is sqrt(SIZE_MAX+1), as s1*s2 <= SIZE_MAX
 * if both s1 < MUL_NO_OVERFLOW and s2 < MUL_NO_OVERFLOW
 */
#define SPOCK_MUL_NO_OVERFLOW	((size_t)1 << (sizeof(size_t) * 4))

void *
spock_reallocarray(void *optr, size_t nmemb, size_t size)
{
		if ((nmemb >= SPOCK_MUL_NO_OVERFLOW || size >= SPOCK_MUL_NO_OVERFLOW) &&
		    nmemb > 0 && SIZE_MAX / nmemb < size) 
		{
			errno = ENOMEM;
			return NULL;
		}
	return spock_xrealloc(optr, size * nmemb);
}
```


Thank you
--

* Thank you for using my tool. Any problem with the tool or suggestion, please open a GitHub issue in this repository. I will be delighted to help anyone.

* **Curious fact:** The name Spock is my dog's name and a little homage to the Star Trek series.


References:
---

* https://www.openssl.org/docs/man1.1.1/man3/SSL_read.html
* https://www.linuxjournal.com/article/7795
* https://www.kernel.org/doc/html/v4.16/userspace-api/seccomp_filter.html
* https://man7.org/linux/man-pages/man8/ld.so.8.html




