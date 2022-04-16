#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/uio.h>
#include <arpa/inet.h>
#include <assert.h>
#include <time.h>
#include <errno.h>

// colors macro
#define RED "\033[22;31m"
#define YELLOW "\033[01;33m"
#define CYAN "\033[22;36m"
#define GREEN "\033[22;32m"
#define LAST "\033[0m"

// anomalys log file
#define SPOCK_LOG "spock_agressors.log"
 
// set zero to stop DEBUG mode
#define SPOCK_BUGVIEW  1
#define SPOCK_DEBUG(x, s...) do { \
 if (!SPOCK_BUGVIEW) { break; } \
 time_t t = time(NULL); \
 char *d = ctime(&t); \
 fprintf(stderr, "\n--- SPOCK DEBUG-START ---\n\n %.*s %s[%d] %s(): \n", \
 (int)strlen(d) - 1, d, __FILE__, \
 __LINE__, __FUNCTION__); \
 fprintf(stderr, x, ## s); \
 fprintf(stderr,"\n\n--- DEBUG-END ---\n"); \
} while (0);
// detect only HTTP anomalys, if set to zero is can be util for AMQ, zeroMQ, gRPC, SMTP, IMAP...
#define SPOCK_ONLY_HTTP 0

// hook rites
#define _CONSTRUCTOR __attribute__((constructor))
#define _DESTRUCTOR __attribute__ ((destructor))
#define SPOCK_LOAD_CALL(var, name) \
	do {\
		const char *err; \
		(var) = dlsym(RTLD_NEXT, (name)); \
		if ((err = dlerror()) != NULL) { \
			fprintf(stderr, "dlsym %s: %s\n", (name), err); \
			exit(EXIT_FAILURE); \
		} \
	} while(0)



struct spock_hook_ctx {
	int logfd;
	int (*SSL_read)(void *ssl, void *buf, int num);
	int (*SSL_get_rfd)(void *ssl);
	int (*SSL_get_wfd)(void *ssl);
};


static struct spock_hook_ctx spock_ctx;

volatile void *spock_burn_mem(volatile void *dst, int c, size_t len) 
{
	volatile char *buf;
   
	for (buf = (volatile char *)dst;  len;  buf[--len] = c);

	return dst;
}

// Deterministic Finite Automata to check if letter exist between a-z or A-Z
int spock_test_letter(char p)
{
	unsigned char yych;

	yych = p;
	switch (yych) {
	case 'A':
	case 'B':
	case 'C':
	case 'D':
	case 'E':
	case 'F':
	case 'G':
	case 'H':
	case 'I':
	case 'J':
	case 'K':
	case 'L':
	case 'M':
	case 'N':
	case 'O':
	case 'P':
	case 'Q':
	case 'R':
	case 'S':
	case 'T':
	case 'U':
	case 'V':
	case 'W':
	case 'X':
	case 'Y':
	case 'Z':
	case 'a':
	case 'b':
	case 'c':
	case 'd':
	case 'e':
	case 'f':
	case 'g':
	case 'h':
	case 'i':
	case 'j':
	case 'k':
	case 'l':
	case 'm':
	case 'n':
	case 'o':
	case 'p':
	case 'q':
	case 'r':
	case 's':
	case 't':
	case 'u':
	case 'v':
	case 'w':
	case 'x':
	case 'y':
	case 'z':	goto yy3;
	default:	goto yy2;
	}
yy2:
	{ return 1; }
yy3:
	++p;
	{ return 0; }
    

}

void _CONSTRUCTOR hook_init(void) 
{
	spock_ctx.logfd = open(SPOCK_LOG, O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);

	if (spock_ctx.logfd < 0) 
	{
		SPOCK_DEBUG("Unable to create %s",SPOCK_LOG);
		exit(0);
	}

	dlerror();
	SPOCK_LOAD_CALL(spock_ctx.SSL_read, "SSL_read");
	SPOCK_LOAD_CALL(spock_ctx.SSL_get_rfd, "SSL_get_rfd");
	SPOCK_LOAD_CALL(spock_ctx.SSL_get_wfd, "SSL_get_wfd");
}


void _DESTRUCTOR hook_end(void) 
{
	close(spock_ctx.logfd);
}



static void *spock_xmalloc_fatal(size_t size) 
{

	SPOCK_DEBUG("\n Memory FAILURE...\n size dbg: %zu\n",size);

	exit(0);
}


void *spock_xmalloc (size_t size) 
{
	void *ptr = malloc (size);

	if (ptr == NULL) 
		return spock_xmalloc_fatal(size);

	return ptr;
}


void *spock_xrealloc(void *ptr, size_t size)
{
	ptr = realloc(ptr, size);
	if (!ptr) {
		SPOCK_DEBUG("realloc failed: %s", strerror(errno));
		exit(0);
	}
	return ptr;
}


// Fork of OpenBSD's function
/*
 * This is sqrt(SIZE_MAX+1), as s1*s2 <= SIZE_MAX
 * if both s1 < MUL_NO_OVERFLOW and s2 < MUL_NO_OVERFLOW
 */
#define SPOCK_MUL_NO_OVERFLOW	((size_t)1 << (sizeof(size_t) * 4))

void *spock_reallocarray(void *optr, size_t nmemb, size_t size)
{
	if ((nmemb >= SPOCK_MUL_NO_OVERFLOW || size >= SPOCK_MUL_NO_OVERFLOW) &&
	    nmemb > 0 && SIZE_MAX / nmemb < size) {
		errno = ENOMEM;
		return NULL;
	}
	return spock_xrealloc(optr, size * nmemb);
}

// Fork of OpenBSD's function
void *spock_xmallocarray(size_t num, size_t size)
{
        void *result = spock_reallocarray(NULL, num, size);

        if (!result) 
        {
                SPOCK_DEBUG("reallocarray failed: %s", strerror(errno));
                exit(0);
        }

        return result;
}


char *all2lowcase(char *str) 
{
	char *str_new=spock_xmallocarray(sizeof(char),strlen(str)+1);
	int i=0;
	
	while(*str != '\0')
	{
		// Deterministic Finite Automata to check letter and case 
		if(!spock_test_letter( *str ) )
		{
			*(str_new+i)=*str | 0x20;	
			i++;
		} else {
			*(str_new+i)=*str;
			i++;
		}


		str++;	
	}


	return str_new;

}

void spock_write_log (char *str)
{
	int fd = open(SPOCK_LOG, O_CREAT | O_WRONLY | O_APPEND, 0760 ); 
	FILE *arq=NULL;

	
	if (-1 != fd) 
	{

		arq = fdopen(fd, "ax");

		if (arq == NULL) 
		{
			SPOCK_DEBUG("error in filename %s  to open() file:  %s",SPOCK_LOG,strerror(errno));		
		    exit(0);
		}

		fprintf(arq,"%s\n",str); 

		if (fclose(arq) == EOF)
		{
			SPOCK_DEBUG("error in Write() file %s",SPOCK_LOG);
			exit(0);
		}
	} else {

		if (close(fd) == -1) 
		{
			
			SPOCK_DEBUG("error in filename %s  to open() file:  %s",SPOCK_LOG,strerror(errno));		
			exit(0);
		}
	}

	arq=NULL; 

}


char *spock_get_ip_str(struct sockaddr *sa, char *s, size_t maxlen)
{
    switch(sa->sa_family) {
        case AF_INET:
            inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr),
                    s, maxlen);
            break;

        case AF_INET6:
            inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr),
                    s, maxlen);
            break;

        default:
            strncpy(s, "Unknown AF", maxlen);
            return NULL;
    }

    return s;
}

bool spock_is_request(char *ptr)
{
	if(ptr == NULL)
		return false;

	if(ptr[0]==' ')
		return false;

	if(ptr[1]==' ')
		return false;

	if(strnlen(ptr,12) < 10)
		return false;

// Sp don't use strcmp() or strncmp() in this point,  because not thread-safe 
// sometimes HTTPd engines uses loop event or threadpool based and can crash strcmp() context.
// is GET ?
 	if(ptr[0]=='G' && ptr[1]=='E' && ptr[2]=='T')
		return true;

// is POST ?
 	if(ptr[0]=='P' && ptr[1]=='O' && ptr[2]=='S' && ptr[3]=='T')
		return true;

// is PUT ?
 	if(ptr[0]=='P' && ptr[1]=='U' && ptr[2]=='T')
		return true;

// is DELETE?
 	if(ptr[0]=='D' && ptr[1]=='E' && ptr[2]=='L' && ptr[3]=='E' && ptr[4]=='T' && ptr[5]=='E')
		return true;

 return false;
}

/*-strnstr() function
 * Copyright (c) 2001 Mike Barcroft <mike@FreeBSD.org>
 * Copyright (c) 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Chris Torek.*/
char *spock_strnstr(const char *s, const char *find, size_t slen)
{
	char c, sc;
	size_t len;

	if ((c = *find++) != '\0') {
		len = strlen(find);
		do {
			do {
				if (slen-- < 1 || (sc = *s++) == '\0')
					return (NULL);
			} while (sc != c);
			if (len > slen)
				return (NULL);
		} while (strncmp(s, find, len) != 0);
		s--;
	}
	return ((char *)s);
}



bool spock_check_block(char *input, int num)
{
	int total_list = 0, total_shellcodes = 0, i = 0;

// use  this point for your custom list of shellcode to block.

#if UINTPTR_MAX == 0xffffffffffffffff
	const char *custom_shellcode[] = {
		"\\x48\\x31\\xc0",                    // xor    rax,rax  X64 LINUX
		"\\x48\\x31\\xdb",                    // xor    rbx,rbx  X64 LINUX
	    "\\x48\\x31\\xff",                    // xor    rdi,rdi  X64 LINUX
	    "\\x48\\x31\\xf6",                    // xor    rsi,rsi  X64 LINUX
	    "\\x48\\x31\\xd2",                    // xor    rdx,rdx  X64 LINUX
	    "\\x48\\x89\\xe6",                    // mov    rsp,rsi  x64 LINUX 
	    "\\x48\\x89\\xe7"                    // mov    rsp,rdi  x64 LINUX
	};
#elif UINTPTR_MAX == 0xffffffff	
		const char *custom_shellcode[] = {
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

	const char *list[] = {
	"\\x90\\x90", // block NOP
	"\\x00\\x00", // nullbyte
	"\\xcd\\x80", // int $0x80 
	"\\xff\\xff",
	"/etc/passwd", // path traversal
	"/etc/shadow",
	"/usr/bin",
	"%s%s%s%s",  // format string...
	"%u%u%u",
	"%x%x%x",
	"%d%d%d",
	"\\..\\..\\..\\..", // path traversal
	"/../../../",
	"\\...\\...",
	"/.../.../.../",
	"%2e%2e%2f%2e%2e%2f",
	"%252e%252e%252f",
	"%c0%ae",
	"%uff0e%uff0e",
	"..%255c..%255c..",
	"..%252f..%252f",
	"%5c..%5c..",
	"%2f..%2f..",
	"0x80000000", // integer overflow maybe
	"0xffffffff",
	"<!--#echo var=",
	"<!--#exec cmd=",
	"autofillupload", // XXE
	"entity xxe",
	"///"
	};

    // prepare context filter
    char *prepared_input=all2lowcase(input);

	total_list = sizeof(list) / sizeof(list[0]);
    total_shellcodes = sizeof(custom_shellcode) / sizeof(custom_shellcode[0]);

	while(i!=total_shellcodes)
	{
		if(spock_strnstr(prepared_input, custom_shellcode[i],num))
		{
			free(prepared_input);
			prepared_input=NULL;
			return true;
		}
		i++;
	}

	i = 0;

	while(i!=total_list)
	{
		if(spock_strnstr(prepared_input, list[i],num))
		{

			free(prepared_input);
			prepared_input=NULL;
			return true;
		}
		i++;
	}

	free(prepared_input);
	return false;
}



bool spock_detect_anomaly( int fd, void *buf, int num) 
{
	struct sockaddr addr;
	socklen_t addrlen = sizeof(struct sockaddr);


	if (getpeername(fd, &addr, &addrlen) < 0) 
	{
		SPOCK_DEBUG("getpeername error\n");
		exit(0);
	}

	if(SPOCK_BUGVIEW==1)
		printf("\n%s---> SPOCK DEBUG MODE <-========\n%s\n=======-> end DEBUG MODE\n%s",CYAN,(char *)buf,LAST);

    	if(SPOCK_ONLY_HTTP==1)
    	{
    		if(spock_is_request((char *)buf)==false)
    			return false;
    	}


	if(spock_check_block((char *)buf,num)==true)
	{
		char *attacker_ip=spock_xmallocarray(129,sizeof(char));
		spock_burn_mem(attacker_ip,0,128); // save one byte for canary, if you compile with full hardening argvs
		spock_get_ip_str(&addr,attacker_ip,128);
		int lenmax=(num+128+128)*sizeof(char);
		char *log_line=spock_xmallocarray(lenmax,sizeof(char));
		spock_burn_mem(log_line,0,lenmax-1);
		time_t rawtime = time(NULL);
		struct tm *ptm = localtime(&rawtime);
 		snprintf(log_line,lenmax-1,"Attacker IP: %s\ndatetime: %02d:%02d:%02d\n===\n%s\n===\n",attacker_ip,ptm->tm_hour,ptm->tm_min, ptm->tm_sec,(char *)buf);

		if(SPOCK_BUGVIEW==1)
			printf("\n%s---> SPOCK DEBUG MODE <-========\n%s\n=======-> end DEBUG MODE\n%s",RED,log_line,LAST);
		
		// write log
        spock_write_log(log_line);

        // free HEAP 
		free(attacker_ip);
		free(log_line);
		attacker_ip=NULL;
		log_line=NULL;

        return true;
	}


	return false;
}


int SSL_read(void *ssl, void *buf, int num) 
{
	int fd, ret;

	ret = spock_ctx.SSL_read(ssl, buf, num);

	if (ssl != NULL && buf != NULL && ret > 0) 
	{
		fd = spock_ctx.SSL_get_rfd(ssl);

		if (fd < 0) 
		{
			fprintf(stderr, "SSL_get_rfd error\n");
			exit(EXIT_FAILURE);
		}

		if(spock_detect_anomaly(fd, buf, ret)==true)
		{
			// SSL_free(ssl); it's a good try if you detect any memory leak
			return 0;
		}
	}

	return ret;
}


