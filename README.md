# Spock SLAF 
Spock SLAF is a **Shared Library Application Firewall**. The principal function is hooking in [OpenSSL's SSL_read()](https://www.openssl.org/docs/man1.1.1/man3/SSL_read.html)
 **OpenSSL's SSL_read()** function to detect anomalies and block and log attacks like buffer overflow, path traversal, XXE and SQL injection. 
<img align="left" width="280" height="240" src="https://github.com/CoolerVoid/spock_slaf/blob/main/doc/spock_slaf_logo.png">
My beginning purpose in this project is to protect any binary that has communication with TLS using OpenSSL resources. 

The motivation for this tool was released during a mitigation project in the past seven years an old. Following my freelancer task, an old client has disclosed a problem around deprecated proprietary binary with many vulnerabilities like Heap buffer overflows, remote buffer overflow and path traversal. The big problem of binary context is the application turn abandonware with no patch fixes, but the enterprise needs to run production loads. So my solution was to insert [seccomp()](https://kubernetes.io/docs/tutorials/security/seccomp/) to restrict syscalls in the process(you know, block calls like system()/execv()). I replaced libc's malloc() with ["DieHard", an error-resistant memory allocator](https://github.com/emeryberger/DieHard). On the other hand, another initiative was little hooking in OpenSSL's SSL_read() function to restrict some evil payloads.

Following additional facts, external rules of server using [BSD's firewall](https://www.openbsd.org/faq/pf/filter.html)(aka packet filter), using custom rules to [allow only by IP and OS fingerprint](https://www.openbsd.org/faq/pf/filter.html#osfp). So that freelancer task stuck in my mind, now you can see my new solution following a global approach to protect TLS communication in the server context.

Features
---
* Action to Block, log and detect security anomalies from SSL_read() input buffers.
* Anyone can load spock_slaf in any Linux binary.
* If detect anomaly in TLS context, Spock saves the IP address of the attacker, date time and attack "payload" register in log file "spock_agressors.log".


The first step to deploy
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
Now you can see the shared library in "bin" directory.

Second step is inject shared library in your binary that uses OpenSSL following communication context(server).
So uses [LD_PRELOAD](https://catonmat.net/simple-ld-preload-tutorial) trick:
```
$ LD_PRELOAD=/home/cooler/spock_slaf/bin/spock_slaf.so.1 bin/optionscat
```
Looking to this example, so has been tested in [OptionsCat financial software](https://github.com/CoolerVoid/optionscat).
If anyone attacks the optionscat server, you can see the full log in the file "spock_agressors.log".

* Thank you for using my tool. Any problem with the tool or suggestion, please open a GitHub issue in this repository. I will be delighted to help anyone.

* **Curious fact:** The name Spock is my dog's name and a little homage to the Star Trek series.


Reference:
---

https://www.openssl.org/docs/man1.1.1/man3/SSL_read.html
https://www.linuxjournal.com/article/7795
https://www.kernel.org/doc/html/v4.16/userspace-api/seccomp_filter.html
https://man7.org/linux/man-pages/man8/ld.so.8.html




