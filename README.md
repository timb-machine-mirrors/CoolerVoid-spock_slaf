# Spock SLAF 
Spock SLAF is a **Shared Library Application Firewall** "SLAF". It has the purpose to protect any service that uses the [OpenSSL library](https://www.openssl.org/docs/man1.1.1/man3/SSL_read.html). The SLAF inserts hooking to intercept all communication to detect security anomalies and block and log attacks like buffer overflow, path traversal, XSS and SQL injection. So to detect anomalies, Spock uses [Deterministic Finite Automaton](https://en.wikipedia.org/wiki/Deterministic_finite_automaton) with rank scores to compute risks and create alerts for each context.

<img align="left" width="280" height="240" src="https://github.com/CoolerVoid/spock_slaf/blob/main/doc/spock_slaf_logo.png">
My beginning purpose in this project is to protect any binary that has communication with TLS using OpenSSL resources. 

## Video demo

https://www.youtube.com/watch?v=Lm3kpA-NZnE

## Etymology

The motivation for this tool was released during a mitigation project in the past seven years an old. Following my freelancer task, an old client has disclosed a problem around deprecated proprietary binary with many vulnerabilities like Heap buffer overflows, remote buffer overflow and path traversal. The big problem of binary context is the application turn abandonware with no patch fixes, but the enterprise needs to run production loads. So my solution was to insert **[seccomp()](https://kubernetes.io/docs/tutorials/security/seccomp/)** to restrict syscalls in the process(you know, block calls like system()/execv()). I replaced libc's malloc() with **["DieHard", an error-resistant memory allocator](https://github.com/emeryberger/DieHard)**. On the other hand, another initiative was little hooking in OpenSSL's SSL_read() function to restrict some evil payloads, another option.

Another option is to use **[libreSSL](https://www.libressl.org/)** and up a monitor to listen if it has a compatibility bug. The lousy point of LibreSSL is the performance; you can see that if you use a tool like gprof to get a benchmark between OpenSSL and LibreSSL. So OpenSSL is cool but not safest like LibreSSL or lib Sodium. Looking at the performance context, if you get arithmetic functions to big int of OpenSSL, some resources like **[Big int operations BN_new()](https://www.openssl.org/docs/man1.0.2/man3/bn.html)** do not have a good performance like **[libGMP](https://gmplib.org/gmp6.1)**. So relax. Performance is not always the best path for security. Security validations and extra buffer and proper bounds checks have an expected cost, without this, you can see a lot of problems for example looking to **[spectre/meltdown](https://meltdownattack.com/)** in the past.

Following additional facts, external rules of server using **[BSD's firewall](https://www.openbsd.org/faq/pf/filter.html)(aka packet filter)**, using custom rules to **[allow only by IP and OS fingerprint](https://www.openbsd.org/faq/pf/filter.html#osfp)**. So that freelancer task stuck in my mind, now you can see my new solution following a global approach to protect TLS communication in the server context.


Features
---
* Action to Block, log and detect security anomalies from SSL_read() input buffers.
* Capacity to run in any programme that uses the OpenSSL library.
* If detect anomaly in TLS context, Spock saves the IP address of the attacker, date time and attack "payload" register in log file "spock_agressors.log".


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



Extra content
--
* You can customize the score rank to detect the anomaly, if set macro **SPOCK_SCORE** to any number between 1 to 10(Low number is more sensitive).
* You can customize the list of attack payloads to block. Please look at the source code.
* You can gain performance in HTTP context, if set macro **SPOCK_ONLY_HTTP to "1"** in the source code.
* You can remove debug mode, if set macro **SPOCK_BUGVIEW to "0"** in the source code.




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




