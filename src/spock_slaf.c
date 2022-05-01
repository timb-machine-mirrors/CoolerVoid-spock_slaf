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
// DFA taint analysis rank to match
#define SPOCK_SCORE 3
 
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
#define SPOCK_ONLY_HTTP 1

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
	int (*SSL_read)(void *ssl, void *buf, int num);
	int (*SSL_get_rfd)(void *ssl);
	int (*SSL_get_wfd)(void *ssl);
};

enum {
  SQLI,XSS,PATHTRAVERSAL,SPOCK_NEW_LINE,SPOCK_END
};

static struct spock_hook_ctx spock_ctx;

void 
spock_write_log (char *str)
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

volatile void *
spock_burn_mem(volatile void *dst, int c, size_t len) 
{
	volatile char *buf;
   
		for (buf = (volatile char *)dst;  len;  buf[--len] = c);

	return dst;
}

int 
spock_dfa_filter(char** p, char** lex)
{
    char* marker;

    for (;;) {
    *lex = *p;
    
#line 132 "<stdout>"
	{
		char yych;
		yych = (char)**p;
		switch (yych) {
		case 0x00:	goto yy2;
		case '\n':	goto yy6;
		case '*':
		case '>':	goto yy8;
		case '.':	goto yy9;
		case 'a':	goto yy10;
		case 'c':	goto yy11;
		case 'd':	goto yy12;
		case 'e':	goto yy13;
		case 'f':	goto yy14;
		case 'i':	goto yy15;
		case 'j':	goto yy16;
		case 'm':	goto yy17;
		case 'o':	goto yy18;
		case 'p':	goto yy19;
		case 's':	goto yy20;
		case 'u':	goto yy21;
		case 'v':	goto yy22;
		case 'w':	goto yy23;
		default:	goto yy4;
		}
yy2:
		++*p;
#line 138 "spock_slaf.c"
		{ return SPOCK_END; }
#line 162 "<stdout>"
yy4:
		++*p;
yy5:
#line 139 "spock_slaf.c"
		{ continue; }
#line 168 "<stdout>"
yy6:
		++*p;
#line 137 "spock_slaf.c"
		{ return SPOCK_NEW_LINE; }
#line 173 "<stdout>"
yy8:
		yych = (char)*(marker = ++*p);
		switch (yych) {
		case '*':
		case '.':
		case '>':
		case 'a':
		case 'c':
		case 'd':
		case 'e':
		case 'f':
		case 'i':
		case 'j':
		case 'm':
		case 'o':
		case 'p':
		case 's':
		case 'u':
		case 'v':
		case 'w':	goto yy25;
		default:	goto yy5;
		}
yy9:
		yych = (char)*(marker = ++*p);
		switch (yych) {
		case '*':
		case '>':
		case 'a':
		case 'c':
		case 'd':
		case 'e':
		case 'f':
		case 'i':
		case 'j':
		case 'm':
		case 'o':
		case 'p':
		case 's':
		case 'u':
		case 'v':
		case 'w':	goto yy25;
		case '.':	goto yy42;
		default:	goto yy5;
		}
yy10:
		yych = (char)*(marker = ++*p);
		switch (yych) {
		case 'l':	goto yy45;
		default:	goto yy5;
		}
yy11:
		yych = (char)*(marker = ++*p);
		switch (yych) {
		case 'o':	goto yy46;
		default:	goto yy5;
		}
yy12:
		yych = (char)*(marker = ++*p);
		switch (yych) {
		case 'e':	goto yy47;
		case 'o':	goto yy48;
		case 'r':	goto yy49;
		default:	goto yy5;
		}
yy13:
		yych = (char)*(marker = ++*p);
		switch (yych) {
		case 't':	goto yy50;
		case 'v':	goto yy51;
		case 'x':	goto yy52;
		default:	goto yy5;
		}
yy14:
		yych = (char)*(marker = ++*p);
		switch (yych) {
		case 'r':	goto yy53;
		default:	goto yy5;
		}
yy15:
		yych = (char)*(marker = ++*p);
		switch (yych) {
		case 'f':	goto yy54;
		case 'n':	goto yy55;
		default:	goto yy5;
		}
yy16:
		yych = (char)*(marker = ++*p);
		switch (yych) {
		case 'a':	goto yy56;
		default:	goto yy5;
		}
yy17:
		yych = (char)*(marker = ++*p);
		switch (yych) {
		case 'a':	goto yy57;
		default:	goto yy5;
		}
yy18:
		yych = (char)*(marker = ++*p);
		switch (yych) {
		case 'n':	goto yy58;
		default:	goto yy5;
		}
yy19:
		yych = (char)*(marker = ++*p);
		switch (yych) {
		case 'a':	goto yy59;
		default:	goto yy5;
		}
yy20:
		yych = (char)*(marker = ++*p);
		switch (yych) {
		case 'c':	goto yy60;
		case 'e':	goto yy61;
		case 'h':	goto yy62;
		case 'l':	goto yy63;
		default:	goto yy5;
		}
yy21:
		yych = (char)*(marker = ++*p);
		switch (yych) {
		case 'n':	goto yy64;
		case 'p':	goto yy65;
		default:	goto yy5;
		}
yy22:
		yych = (char)*(marker = ++*p);
		switch (yych) {
		case 'e':	goto yy66;
		default:	goto yy5;
		}
yy23:
		yych = (char)*(marker = ++*p);
		switch (yych) {
		case 'h':	goto yy67;
		default:	goto yy5;
		}
yy24:
		yych = (char)*++*p;
yy25:
		switch (yych) {
		case '*':
		case '>':	goto yy24;
		case '.':	goto yy27;
		case 'a':	goto yy28;
		case 'c':	goto yy29;
		case 'd':	goto yy30;
		case 'e':	goto yy31;
		case 'f':	goto yy32;
		case 'i':	goto yy33;
		case 'j':	goto yy34;
		case 'm':	goto yy35;
		case 'o':	goto yy36;
		case 'p':	goto yy37;
		case 's':	goto yy38;
		case 'u':	goto yy39;
		case 'v':	goto yy40;
		case 'w':	goto yy41;
		default:	goto yy26;
		}
yy26:
		*p = marker;
		goto yy5;
yy27:
		yych = (char)*++*p;
		switch (yych) {
		case '*':
		case '>':	goto yy24;
		case '.':	goto yy42;
		case 'a':	goto yy28;
		case 'c':	goto yy29;
		case 'd':	goto yy30;
		case 'e':	goto yy31;
		case 'f':	goto yy32;
		case 'i':	goto yy33;
		case 'j':	goto yy34;
		case 'm':	goto yy35;
		case 'o':	goto yy36;
		case 'p':	goto yy37;
		case 's':	goto yy38;
		case 'u':	goto yy39;
		case 'v':	goto yy40;
		case 'w':	goto yy41;
		default:	goto yy26;
		}
yy28:
		yych = (char)*++*p;
		switch (yych) {
		case 'l':	goto yy45;
		default:	goto yy26;
		}
yy29:
		yych = (char)*++*p;
		switch (yych) {
		case 'o':	goto yy46;
		default:	goto yy26;
		}
yy30:
		yych = (char)*++*p;
		switch (yych) {
		case 'e':	goto yy47;
		case 'o':	goto yy48;
		case 'r':	goto yy49;
		default:	goto yy26;
		}
yy31:
		yych = (char)*++*p;
		switch (yych) {
		case 't':	goto yy50;
		case 'v':	goto yy51;
		case 'x':	goto yy52;
		default:	goto yy26;
		}
yy32:
		yych = (char)*++*p;
		switch (yych) {
		case 'r':	goto yy53;
		default:	goto yy26;
		}
yy33:
		yych = (char)*++*p;
		switch (yych) {
		case 'f':	goto yy54;
		case 'n':	goto yy55;
		default:	goto yy26;
		}
yy34:
		yych = (char)*++*p;
		switch (yych) {
		case 'a':	goto yy56;
		default:	goto yy26;
		}
yy35:
		yych = (char)*++*p;
		switch (yych) {
		case 'a':	goto yy57;
		default:	goto yy26;
		}
yy36:
		yych = (char)*++*p;
		switch (yych) {
		case 'n':	goto yy58;
		default:	goto yy26;
		}
yy37:
		yych = (char)*++*p;
		switch (yych) {
		case 'a':	goto yy59;
		default:	goto yy26;
		}
yy38:
		yych = (char)*++*p;
		switch (yych) {
		case 'c':	goto yy60;
		case 'e':	goto yy61;
		case 'h':	goto yy62;
		case 'l':	goto yy63;
		default:	goto yy26;
		}
yy39:
		yych = (char)*++*p;
		switch (yych) {
		case 'n':	goto yy64;
		case 'p':	goto yy65;
		default:	goto yy26;
		}
yy40:
		yych = (char)*++*p;
		switch (yych) {
		case 'e':	goto yy66;
		default:	goto yy26;
		}
yy41:
		yych = (char)*++*p;
		switch (yych) {
		case 'h':	goto yy67;
		default:	goto yy26;
		}
yy42:
		yych = (char)*++*p;
		switch (yych) {
		case '\n':	goto yy44;
		case '*':
		case '.':
		case '>':	goto yy42;
		case 'a':	goto yy70;
		case 'c':	goto yy71;
		case 'd':	goto yy72;
		case 'e':	goto yy73;
		case 'f':	goto yy74;
		case 'i':	goto yy75;
		case 'j':	goto yy76;
		case 'm':	goto yy77;
		case 'o':	goto yy78;
		case 's':	goto yy79;
		case 'u':	goto yy80;
		case 'v':	goto yy81;
		case 'w':	goto yy82;
		default:	goto yy68;
		}
yy44:
#line 136 "spock_slaf.c"
		{ return PATHTRAVERSAL; }
#line 477 "<stdout>"
yy45:
		yych = (char)*++*p;
		switch (yych) {
		case 'e':	goto yy83;
		default:	goto yy26;
		}
yy46:
		yych = (char)*++*p;
		switch (yych) {
		case 'o':	goto yy84;
		default:	goto yy26;
		}
yy47:
		yych = (char)*++*p;
		switch (yych) {
		case 'l':	goto yy85;
		default:	goto yy26;
		}
yy48:
		yych = (char)*++*p;
		switch (yych) {
		case 'c':	goto yy86;
		default:	goto yy26;
		}
yy49:
		yych = (char)*++*p;
		switch (yych) {
		case 'o':	goto yy87;
		default:	goto yy26;
		}
yy50:
		yych = (char)*++*p;
		switch (yych) {
		case 'c':	goto yy68;
		default:	goto yy26;
		}
yy51:
		yych = (char)*++*p;
		switch (yych) {
		case 'a':	goto yy88;
		default:	goto yy26;
		}
yy52:
		yych = (char)*++*p;
		switch (yych) {
		case 'p':	goto yy89;
		default:	goto yy26;
		}
yy53:
		yych = (char)*++*p;
		switch (yych) {
		case 'o':	goto yy90;
		default:	goto yy26;
		}
yy54:
		yych = (char)*++*p;
		switch (yych) {
		case 'r':	goto yy91;
		default:	goto yy26;
		}
yy55:
		yych = (char)*++*p;
		switch (yych) {
		case 's':	goto yy92;
		default:	goto yy26;
		}
yy56:
		yych = (char)*++*p;
		switch (yych) {
		case 'v':	goto yy93;
		default:	goto yy26;
		}
yy57:
		yych = (char)*++*p;
		switch (yych) {
		case 'p':	goto yy94;
		case 't':	goto yy95;
		default:	goto yy26;
		}
yy58:
		yych = (char)*++*p;
		switch (yych) {
		case 'c':	goto yy96;
		case 'e':	goto yy97;
		case 'f':	goto yy98;
		case 'l':	goto yy99;
		case 'm':	goto yy100;
		case 'p':	goto yy101;
		case 's':	goto yy102;
		default:	goto yy26;
		}
yy59:
		yych = (char)*++*p;
		switch (yych) {
		case 's':	goto yy103;
		default:	goto yy26;
		}
yy60:
		yych = (char)*++*p;
		switch (yych) {
		case 'r':	goto yy104;
		default:	goto yy26;
		}
yy61:
		yych = (char)*++*p;
		switch (yych) {
		case 'l':	goto yy105;
		default:	goto yy26;
		}
yy62:
		yych = (char)*++*p;
		switch (yych) {
		case 'a':	goto yy106;
		default:	goto yy26;
		}
yy63:
		yych = (char)*++*p;
		switch (yych) {
		case 'e':	goto yy107;
		default:	goto yy26;
		}
yy64:
		yych = (char)*++*p;
		switch (yych) {
		case 'i':	goto yy108;
		default:	goto yy26;
		}
yy65:
		yych = (char)*++*p;
		switch (yych) {
		case 'd':	goto yy109;
		default:	goto yy26;
		}
yy66:
		yych = (char)*++*p;
		switch (yych) {
		case 'r':	goto yy110;
		default:	goto yy26;
		}
yy67:
		yych = (char)*++*p;
		switch (yych) {
		case 'e':	goto yy111;
		default:	goto yy26;
		}
yy68:
		yych = (char)*++*p;
yy69:
		switch (yych) {
		case '\n':	goto yy44;
		default:	goto yy68;
		}
yy70:
		yych = (char)*++*p;
		switch (yych) {
		case 'l':	goto yy112;
		default:	goto yy69;
		}
yy71:
		yych = (char)*++*p;
		switch (yych) {
		case 'o':	goto yy113;
		default:	goto yy69;
		}
yy72:
		yych = (char)*++*p;
		switch (yych) {
		case 'e':	goto yy114;
		case 'o':	goto yy115;
		case 'r':	goto yy116;
		default:	goto yy69;
		}
yy73:
		yych = (char)*++*p;
		switch (yych) {
		case 'v':	goto yy117;
		case 'x':	goto yy118;
		default:	goto yy69;
		}
yy74:
		yych = (char)*++*p;
		switch (yych) {
		case 'r':	goto yy119;
		default:	goto yy69;
		}
yy75:
		yych = (char)*++*p;
		switch (yych) {
		case 'f':	goto yy120;
		case 'n':	goto yy121;
		default:	goto yy69;
		}
yy76:
		yych = (char)*++*p;
		switch (yych) {
		case 'a':	goto yy122;
		default:	goto yy69;
		}
yy77:
		yych = (char)*++*p;
		switch (yych) {
		case 'a':	goto yy123;
		default:	goto yy69;
		}
yy78:
		yych = (char)*++*p;
		switch (yych) {
		case 'n':	goto yy124;
		default:	goto yy69;
		}
yy79:
		yych = (char)*++*p;
		switch (yych) {
		case 'c':	goto yy125;
		case 'e':	goto yy126;
		case 'l':	goto yy127;
		default:	goto yy69;
		}
yy80:
		yych = (char)*++*p;
		switch (yych) {
		case 'n':	goto yy128;
		case 'p':	goto yy129;
		default:	goto yy69;
		}
yy81:
		yych = (char)*++*p;
		switch (yych) {
		case 'e':	goto yy130;
		default:	goto yy69;
		}
yy82:
		yych = (char)*++*p;
		switch (yych) {
		case 'h':	goto yy131;
		default:	goto yy69;
		}
yy83:
		yych = (char)*++*p;
		switch (yych) {
		case 'r':	goto yy132;
		default:	goto yy26;
		}
yy84:
		yych = (char)*++*p;
		switch (yych) {
		case 'k':	goto yy133;
		default:	goto yy26;
		}
yy85:
		yych = (char)*++*p;
		switch (yych) {
		case 'e':	goto yy134;
		default:	goto yy26;
		}
yy86:
		yych = (char)*++*p;
		switch (yych) {
		case 'u':	goto yy135;
		default:	goto yy26;
		}
yy87:
		yych = (char)*++*p;
		switch (yych) {
		case 'p':	goto yy136;
		default:	goto yy26;
		}
yy88:
		yych = (char)*++*p;
		switch (yych) {
		case 'l':	goto yy139;
		default:	goto yy26;
		}
yy89:
		yych = (char)*++*p;
		switch (yych) {
		case 'r':	goto yy142;
		default:	goto yy26;
		}
yy90:
		yych = (char)*++*p;
		switch (yych) {
		case 'm':	goto yy143;
		default:	goto yy26;
		}
yy91:
		yych = (char)*++*p;
		switch (yych) {
		case 'a':	goto yy144;
		default:	goto yy26;
		}
yy92:
		yych = (char)*++*p;
		switch (yych) {
		case 'e':	goto yy145;
		default:	goto yy26;
		}
yy93:
		yych = (char)*++*p;
		switch (yych) {
		case 'a':	goto yy146;
		default:	goto yy26;
		}
yy94:
		yych = (char)*++*p;
		switch (yych) {
		case 'R':	goto yy147;
		default:	goto yy26;
		}
yy95:
		yych = (char)*++*p;
		switch (yych) {
		case 'c':	goto yy148;
		default:	goto yy26;
		}
yy96:
		yych = (char)*++*p;
		switch (yych) {
		case 'l':	goto yy149;
		default:	goto yy26;
		}
yy97:
		yych = (char)*++*p;
		switch (yych) {
		case 'r':	goto yy150;
		default:	goto yy26;
		}
yy98:
		yych = (char)*++*p;
		switch (yych) {
		case 'i':	goto yy151;
		default:	goto yy26;
		}
yy99:
		yych = (char)*++*p;
		switch (yych) {
		case 'o':	goto yy152;
		default:	goto yy26;
		}
yy100:
		yych = (char)*++*p;
		switch (yych) {
		case 'o':	goto yy153;
		default:	goto yy26;
		}
yy101:
		yych = (char)*++*p;
		switch (yych) {
		case 'a':	goto yy154;
		case 'r':	goto yy155;
		default:	goto yy26;
		}
yy102:
		yych = (char)*++*p;
		switch (yych) {
		case 't':	goto yy156;
		default:	goto yy26;
		}
yy103:
		yych = (char)*++*p;
		switch (yych) {
		case 's':	goto yy157;
		default:	goto yy26;
		}
yy104:
		yych = (char)*++*p;
		switch (yych) {
		case 'i':	goto yy158;
		default:	goto yy26;
		}
yy105:
		yych = (char)*++*p;
		switch (yych) {
		case 'e':	goto yy159;
		default:	goto yy26;
		}
yy106:
		yych = (char)*++*p;
		switch (yych) {
		case 'd':	goto yy160;
		default:	goto yy26;
		}
yy107:
		yych = (char)*++*p;
		switch (yych) {
		case 'e':	goto yy87;
		default:	goto yy26;
		}
yy108:
		yych = (char)*++*p;
		switch (yych) {
		case 'o':	goto yy161;
		default:	goto yy26;
		}
yy109:
		yych = (char)*++*p;
		switch (yych) {
		case 'a':	goto yy134;
		default:	goto yy26;
		}
yy110:
		yych = (char)*++*p;
		switch (yych) {
		case 's':	goto yy64;
		default:	goto yy26;
		}
yy111:
		yych = (char)*++*p;
		switch (yych) {
		case 'r':	goto yy162;
		default:	goto yy26;
		}
yy112:
		yych = (char)*++*p;
		switch (yych) {
		case 'e':	goto yy163;
		default:	goto yy69;
		}
yy113:
		yych = (char)*++*p;
		switch (yych) {
		case 'o':	goto yy164;
		default:	goto yy69;
		}
yy114:
		yych = (char)*++*p;
		switch (yych) {
		case 'l':	goto yy165;
		default:	goto yy69;
		}
yy115:
		yych = (char)*++*p;
		switch (yych) {
		case 'c':	goto yy166;
		default:	goto yy69;
		}
yy116:
		yych = (char)*++*p;
		switch (yych) {
		case 'o':	goto yy167;
		default:	goto yy69;
		}
yy117:
		yych = (char)*++*p;
		switch (yych) {
		case 'a':	goto yy168;
		default:	goto yy69;
		}
yy118:
		yych = (char)*++*p;
		switch (yych) {
		case 'p':	goto yy169;
		default:	goto yy69;
		}
yy119:
		yych = (char)*++*p;
		switch (yych) {
		case 'o':	goto yy170;
		default:	goto yy69;
		}
yy120:
		yych = (char)*++*p;
		switch (yych) {
		case 'r':	goto yy171;
		default:	goto yy69;
		}
yy121:
		yych = (char)*++*p;
		switch (yych) {
		case 's':	goto yy172;
		default:	goto yy69;
		}
yy122:
		yych = (char)*++*p;
		switch (yych) {
		case 'v':	goto yy173;
		default:	goto yy69;
		}
yy123:
		yych = (char)*++*p;
		switch (yych) {
		case 'p':	goto yy174;
		case 't':	goto yy175;
		default:	goto yy69;
		}
yy124:
		yych = (char)*++*p;
		switch (yych) {
		case 'c':	goto yy176;
		case 'e':	goto yy177;
		case 'f':	goto yy178;
		case 'l':	goto yy179;
		case 'm':	goto yy180;
		case 'p':	goto yy181;
		case 's':	goto yy182;
		default:	goto yy69;
		}
yy125:
		yych = (char)*++*p;
		switch (yych) {
		case 'r':	goto yy183;
		default:	goto yy69;
		}
yy126:
		yych = (char)*++*p;
		switch (yych) {
		case 'l':	goto yy184;
		default:	goto yy69;
		}
yy127:
		yych = (char)*++*p;
		switch (yych) {
		case 'e':	goto yy185;
		default:	goto yy69;
		}
yy128:
		yych = (char)*++*p;
		switch (yych) {
		case 'i':	goto yy186;
		default:	goto yy69;
		}
yy129:
		yych = (char)*++*p;
		switch (yych) {
		case 'd':	goto yy187;
		default:	goto yy69;
		}
yy130:
		yych = (char)*++*p;
		switch (yych) {
		case 'r':	goto yy188;
		default:	goto yy69;
		}
yy131:
		yych = (char)*++*p;
		switch (yych) {
		case 'e':	goto yy189;
		default:	goto yy69;
		}
yy132:
		yych = (char)*++*p;
		switch (yych) {
		case 't':	goto yy139;
		default:	goto yy26;
		}
yy133:
		yych = (char)*++*p;
		switch (yych) {
		case 'i':	goto yy190;
		default:	goto yy26;
		}
yy134:
		yych = (char)*++*p;
		switch (yych) {
		case 't':	goto yy162;
		default:	goto yy26;
		}
yy135:
		yych = (char)*++*p;
		switch (yych) {
		case 'm':	goto yy191;
		default:	goto yy26;
		}
yy136:
		yych = (char)*++*p;
		switch (yych) {
		case '\n':	goto yy138;
		default:	goto yy136;
		}
yy138:
#line 134 "spock_slaf.c"
		{ return SQLI; }
#line 1050 "<stdout>"
yy139:
		yych = (char)*++*p;
		switch (yych) {
		case '\n':	goto yy141;
		default:	goto yy139;
		}
yy141:
#line 135 "spock_slaf.c"
		{ return XSS; }
#line 1060 "<stdout>"
yy142:
		yych = (char)*++*p;
		switch (yych) {
		case 'e':	goto yy192;
		default:	goto yy26;
		}
yy143:
		yych = (char)*++*p;
		switch (yych) {
		case 'C':	goto yy193;
		default:	goto yy26;
		}
yy144:
		yych = (char)*++*p;
		switch (yych) {
		case 'm':	goto yy190;
		default:	goto yy26;
		}
yy145:
		yych = (char)*++*p;
		switch (yych) {
		case 'r':	goto yy194;
		default:	goto yy26;
		}
yy146:
		yych = (char)*++*p;
		switch (yych) {
		case 's':	goto yy195;
		default:	goto yy26;
		}
yy147:
		yych = (char)*++*p;
		switch (yych) {
		case 'e':	goto yy196;
		default:	goto yy26;
		}
yy148:
		yych = (char)*++*p;
		switch (yych) {
		case 'h':	goto yy136;
		default:	goto yy26;
		}
yy149:
		yych = (char)*++*p;
		switch (yych) {
		case 'i':	goto yy197;
		default:	goto yy26;
		}
yy150:
		yych = (char)*++*p;
		switch (yych) {
		case 'r':	goto yy198;
		default:	goto yy26;
		}
yy151:
		yych = (char)*++*p;
		switch (yych) {
		case 'n':	goto yy199;
		default:	goto yy26;
		}
yy152:
		yych = (char)*++*p;
		switch (yych) {
		case 'a':	goto yy200;
		default:	goto yy26;
		}
yy153:
		yych = (char)*++*p;
		switch (yych) {
		case 'u':	goto yy201;
		default:	goto yy26;
		}
yy154:
		yych = (char)*++*p;
		switch (yych) {
		case 'g':	goto yy202;
		default:	goto yy26;
		}
yy155:
		yych = (char)*++*p;
		switch (yych) {
		case 'o':	goto yy203;
		default:	goto yy26;
		}
yy156:
		yych = (char)*++*p;
		switch (yych) {
		case 'a':	goto yy83;
		default:	goto yy26;
		}
yy157:
		yych = (char)*++*p;
		switch (yych) {
		case 'w':	goto yy204;
		default:	goto yy26;
		}
yy158:
		yych = (char)*++*p;
		switch (yych) {
		case 'p':	goto yy132;
		default:	goto yy26;
		}
yy159:
		yych = (char)*++*p;
		switch (yych) {
		case 'c':	goto yy194;
		default:	goto yy26;
		}
yy160:
		yych = (char)*++*p;
		switch (yych) {
		case 'o':	goto yy205;
		default:	goto yy26;
		}
yy161:
		yych = (char)*++*p;
		switch (yych) {
		case 'n':	goto yy136;
		default:	goto yy26;
		}
yy162:
		yych = (char)*++*p;
		switch (yych) {
		case 'e':	goto yy136;
		default:	goto yy26;
		}
yy163:
		yych = (char)*++*p;
		switch (yych) {
		case 'r':	goto yy206;
		default:	goto yy69;
		}
yy164:
		yych = (char)*++*p;
		switch (yych) {
		case 'k':	goto yy207;
		default:	goto yy69;
		}
yy165:
		yych = (char)*++*p;
		switch (yych) {
		case 'e':	goto yy208;
		default:	goto yy69;
		}
yy166:
		yych = (char)*++*p;
		switch (yych) {
		case 'u':	goto yy209;
		default:	goto yy69;
		}
yy167:
		yych = (char)*++*p;
		switch (yych) {
		case 'p':	goto yy136;
		default:	goto yy69;
		}
yy168:
		yych = (char)*++*p;
		switch (yych) {
		case 'l':	goto yy139;
		default:	goto yy69;
		}
yy169:
		yych = (char)*++*p;
		switch (yych) {
		case 'r':	goto yy210;
		default:	goto yy69;
		}
yy170:
		yych = (char)*++*p;
		switch (yych) {
		case 'm':	goto yy211;
		default:	goto yy69;
		}
yy171:
		yych = (char)*++*p;
		switch (yych) {
		case 'a':	goto yy212;
		default:	goto yy69;
		}
yy172:
		yych = (char)*++*p;
		switch (yych) {
		case 'e':	goto yy213;
		default:	goto yy69;
		}
yy173:
		yych = (char)*++*p;
		switch (yych) {
		case 'a':	goto yy214;
		default:	goto yy69;
		}
yy174:
		yych = (char)*++*p;
		switch (yych) {
		case 'R':	goto yy215;
		default:	goto yy69;
		}
yy175:
		yych = (char)*++*p;
		switch (yych) {
		case 'c':	goto yy216;
		default:	goto yy69;
		}
yy176:
		yych = (char)*++*p;
		switch (yych) {
		case 'l':	goto yy217;
		default:	goto yy69;
		}
yy177:
		yych = (char)*++*p;
		switch (yych) {
		case 'r':	goto yy218;
		default:	goto yy69;
		}
yy178:
		yych = (char)*++*p;
		switch (yych) {
		case 'i':	goto yy219;
		default:	goto yy69;
		}
yy179:
		yych = (char)*++*p;
		switch (yych) {
		case 'o':	goto yy220;
		default:	goto yy69;
		}
yy180:
		yych = (char)*++*p;
		switch (yych) {
		case 'o':	goto yy221;
		default:	goto yy69;
		}
yy181:
		yych = (char)*++*p;
		switch (yych) {
		case 'a':	goto yy222;
		case 'r':	goto yy223;
		default:	goto yy69;
		}
yy182:
		yych = (char)*++*p;
		switch (yych) {
		case 't':	goto yy224;
		default:	goto yy69;
		}
yy183:
		yych = (char)*++*p;
		switch (yych) {
		case 'i':	goto yy225;
		default:	goto yy69;
		}
yy184:
		yych = (char)*++*p;
		switch (yych) {
		case 'e':	goto yy226;
		default:	goto yy69;
		}
yy185:
		yych = (char)*++*p;
		switch (yych) {
		case 'e':	goto yy167;
		default:	goto yy69;
		}
yy186:
		yych = (char)*++*p;
		switch (yych) {
		case 'o':	goto yy227;
		default:	goto yy69;
		}
yy187:
		yych = (char)*++*p;
		switch (yych) {
		case 'a':	goto yy208;
		default:	goto yy69;
		}
yy188:
		yych = (char)*++*p;
		switch (yych) {
		case 's':	goto yy128;
		default:	goto yy69;
		}
yy189:
		yych = (char)*++*p;
		switch (yych) {
		case 'r':	goto yy228;
		default:	goto yy69;
		}
yy190:
		yych = (char)*++*p;
		switch (yych) {
		case 'e':	goto yy139;
		default:	goto yy26;
		}
yy191:
		yych = (char)*++*p;
		switch (yych) {
		case 'e':	goto yy229;
		default:	goto yy26;
		}
yy192:
		yych = (char)*++*p;
		switch (yych) {
		case 's':	goto yy230;
		default:	goto yy26;
		}
yy193:
		yych = (char)*++*p;
		switch (yych) {
		case 'h':	goto yy231;
		default:	goto yy26;
		}
yy194:
		yych = (char)*++*p;
		switch (yych) {
		case 't':	goto yy136;
		default:	goto yy26;
		}
yy195:
		yych = (char)*++*p;
		switch (yych) {
		case 'c':	goto yy60;
		default:	goto yy26;
		}
yy196:
		yych = (char)*++*p;
		switch (yych) {
		case 'd':	goto yy232;
		default:	goto yy26;
		}
yy197:
		yych = (char)*++*p;
		switch (yych) {
		case 'c':	goto yy233;
		default:	goto yy26;
		}
yy198:
		yych = (char)*++*p;
		switch (yych) {
		case 'o':	goto yy234;
		default:	goto yy26;
		}
yy199:
		yych = (char)*++*p;
		switch (yych) {
		case 'i':	goto yy235;
		default:	goto yy26;
		}
yy200:
		yych = (char)*++*p;
		switch (yych) {
		case 'd':	goto yy139;
		default:	goto yy26;
		}
yy201:
		yych = (char)*++*p;
		switch (yych) {
		case 's':	goto yy236;
		default:	goto yy26;
		}
yy202:
		yych = (char)*++*p;
		switch (yych) {
		case 'e':	goto yy237;
		default:	goto yy26;
		}
yy203:
		yych = (char)*++*p;
		switch (yych) {
		case 'g':	goto yy238;
		default:	goto yy26;
		}
yy204:
		yych = (char)*++*p;
		switch (yych) {
		case 'o':	goto yy239;
		default:	goto yy26;
		}
yy205:
		yych = (char)*++*p;
		switch (yych) {
		case 'w':	goto yy68;
		default:	goto yy26;
		}
yy206:
		yych = (char)*++*p;
		switch (yych) {
		case 't':	goto yy139;
		default:	goto yy69;
		}
yy207:
		yych = (char)*++*p;
		switch (yych) {
		case 'i':	goto yy240;
		default:	goto yy69;
		}
yy208:
		yych = (char)*++*p;
		switch (yych) {
		case 't':	goto yy228;
		default:	goto yy69;
		}
yy209:
		yych = (char)*++*p;
		switch (yych) {
		case 'm':	goto yy241;
		default:	goto yy69;
		}
yy210:
		yych = (char)*++*p;
		switch (yych) {
		case 'e':	goto yy242;
		default:	goto yy69;
		}
yy211:
		yych = (char)*++*p;
		switch (yych) {
		case 'C':	goto yy243;
		default:	goto yy69;
		}
yy212:
		yych = (char)*++*p;
		switch (yych) {
		case 'm':	goto yy240;
		default:	goto yy69;
		}
yy213:
		yych = (char)*++*p;
		switch (yych) {
		case 'r':	goto yy244;
		default:	goto yy69;
		}
yy214:
		yych = (char)*++*p;
		switch (yych) {
		case 's':	goto yy245;
		default:	goto yy69;
		}
yy215:
		yych = (char)*++*p;
		switch (yych) {
		case 'e':	goto yy246;
		default:	goto yy69;
		}
yy216:
		yych = (char)*++*p;
		switch (yych) {
		case 'h':	goto yy136;
		default:	goto yy69;
		}
yy217:
		yych = (char)*++*p;
		switch (yych) {
		case 'i':	goto yy247;
		default:	goto yy69;
		}
yy218:
		yych = (char)*++*p;
		switch (yych) {
		case 'r':	goto yy248;
		default:	goto yy69;
		}
yy219:
		yych = (char)*++*p;
		switch (yych) {
		case 'n':	goto yy249;
		default:	goto yy69;
		}
yy220:
		yych = (char)*++*p;
		switch (yych) {
		case 'a':	goto yy250;
		default:	goto yy69;
		}
yy221:
		yych = (char)*++*p;
		switch (yych) {
		case 'u':	goto yy251;
		default:	goto yy69;
		}
yy222:
		yych = (char)*++*p;
		switch (yych) {
		case 'g':	goto yy252;
		default:	goto yy69;
		}
yy223:
		yych = (char)*++*p;
		switch (yych) {
		case 'o':	goto yy253;
		default:	goto yy69;
		}
yy224:
		yych = (char)*++*p;
		switch (yych) {
		case 'a':	goto yy163;
		default:	goto yy69;
		}
yy225:
		yych = (char)*++*p;
		switch (yych) {
		case 'p':	goto yy206;
		default:	goto yy69;
		}
yy226:
		yych = (char)*++*p;
		switch (yych) {
		case 'c':	goto yy244;
		default:	goto yy69;
		}
yy227:
		yych = (char)*++*p;
		switch (yych) {
		case 'n':	goto yy136;
		default:	goto yy69;
		}
yy228:
		yych = (char)*++*p;
		switch (yych) {
		case 'e':	goto yy136;
		default:	goto yy69;
		}
yy229:
		yych = (char)*++*p;
		switch (yych) {
		case 'n':	goto yy132;
		default:	goto yy26;
		}
yy230:
		yych = (char)*++*p;
		switch (yych) {
		case 's':	goto yy254;
		default:	goto yy26;
		}
yy231:
		yych = (char)*++*p;
		switch (yych) {
		case 'a':	goto yy255;
		default:	goto yy26;
		}
yy232:
		yych = (char)*++*p;
		switch (yych) {
		case 'u':	goto yy256;
		default:	goto yy26;
		}
yy233:
		yych = (char)*++*p;
		switch (yych) {
		case 'k':	goto yy139;
		default:	goto yy26;
		}
yy234:
		yych = (char)*++*p;
		switch (yych) {
		case 'r':	goto yy139;
		default:	goto yy26;
		}
yy235:
		yych = (char)*++*p;
		switch (yych) {
		case 's':	goto yy257;
		default:	goto yy26;
		}
yy236:
		yych = (char)*++*p;
		switch (yych) {
		case 'e':	goto yy258;
		default:	goto yy26;
		}
yy237:
		yych = (char)*++*p;
		switch (yych) {
		case 's':	goto yy259;
		default:	goto yy26;
		}
yy238:
		yych = (char)*++*p;
		switch (yych) {
		case 'r':	goto yy260;
		default:	goto yy26;
		}
yy239:
		yych = (char)*++*p;
		switch (yych) {
		case 'r':	goto yy261;
		default:	goto yy26;
		}
yy240:
		yych = (char)*++*p;
		switch (yych) {
		case 'e':	goto yy139;
		default:	goto yy69;
		}
yy241:
		yych = (char)*++*p;
		switch (yych) {
		case 'e':	goto yy262;
		default:	goto yy69;
		}
yy242:
		yych = (char)*++*p;
		switch (yych) {
		case 's':	goto yy263;
		default:	goto yy69;
		}
yy243:
		yych = (char)*++*p;
		switch (yych) {
		case 'h':	goto yy264;
		default:	goto yy69;
		}
yy244:
		yych = (char)*++*p;
		switch (yych) {
		case 't':	goto yy136;
		default:	goto yy69;
		}
yy245:
		yych = (char)*++*p;
		switch (yych) {
		case 'c':	goto yy125;
		default:	goto yy69;
		}
yy246:
		yych = (char)*++*p;
		switch (yych) {
		case 'd':	goto yy265;
		default:	goto yy69;
		}
yy247:
		yych = (char)*++*p;
		switch (yych) {
		case 'c':	goto yy266;
		default:	goto yy69;
		}
yy248:
		yych = (char)*++*p;
		switch (yych) {
		case 'o':	goto yy267;
		default:	goto yy69;
		}
yy249:
		yych = (char)*++*p;
		switch (yych) {
		case 'i':	goto yy268;
		default:	goto yy69;
		}
yy250:
		yych = (char)*++*p;
		switch (yych) {
		case 'd':	goto yy139;
		default:	goto yy69;
		}
yy251:
		yych = (char)*++*p;
		switch (yych) {
		case 's':	goto yy269;
		default:	goto yy69;
		}
yy252:
		yych = (char)*++*p;
		switch (yych) {
		case 'e':	goto yy270;
		default:	goto yy69;
		}
yy253:
		yych = (char)*++*p;
		switch (yych) {
		case 'g':	goto yy271;
		default:	goto yy69;
		}
yy254:
		yych = (char)*++*p;
		switch (yych) {
		case 'i':	goto yy272;
		default:	goto yy26;
		}
yy255:
		yych = (char)*++*p;
		switch (yych) {
		case 'r':	goto yy273;
		default:	goto yy26;
		}
yy256:
		yych = (char)*++*p;
		switch (yych) {
		case 'c':	goto yy162;
		default:	goto yy26;
		}
yy257:
		yych = (char)*++*p;
		switch (yych) {
		case 'h':	goto yy139;
		default:	goto yy26;
		}
yy258:
		yych = (char)*++*p;
		switch (yych) {
		case 'o':	goto yy274;
		default:	goto yy26;
		}
yy259:
		yych = (char)*++*p;
		switch (yych) {
		case 'h':	goto yy275;
		default:	goto yy26;
		}
yy260:
		yych = (char)*++*p;
		switch (yych) {
		case 'e':	goto yy276;
		default:	goto yy26;
		}
yy261:
		yych = (char)*++*p;
		switch (yych) {
		case 'd':	goto yy68;
		default:	goto yy26;
		}
yy262:
		yych = (char)*++*p;
		switch (yych) {
		case 'n':	goto yy206;
		default:	goto yy69;
		}
yy263:
		yych = (char)*++*p;
		switch (yych) {
		case 's':	goto yy277;
		default:	goto yy69;
		}
yy264:
		yych = (char)*++*p;
		switch (yych) {
		case 'a':	goto yy278;
		default:	goto yy69;
		}
yy265:
		yych = (char)*++*p;
		switch (yych) {
		case 'u':	goto yy279;
		default:	goto yy69;
		}
yy266:
		yych = (char)*++*p;
		switch (yych) {
		case 'k':	goto yy139;
		default:	goto yy69;
		}
yy267:
		yych = (char)*++*p;
		switch (yych) {
		case 'r':	goto yy139;
		default:	goto yy69;
		}
yy268:
		yych = (char)*++*p;
		switch (yych) {
		case 's':	goto yy280;
		default:	goto yy69;
		}
yy269:
		yych = (char)*++*p;
		switch (yych) {
		case 'e':	goto yy281;
		default:	goto yy69;
		}
yy270:
		yych = (char)*++*p;
		switch (yych) {
		case 's':	goto yy282;
		default:	goto yy69;
		}
yy271:
		yych = (char)*++*p;
		switch (yych) {
		case 'r':	goto yy283;
		default:	goto yy69;
		}
yy272:
		yych = (char)*++*p;
		switch (yych) {
		case 'o':	goto yy284;
		default:	goto yy26;
		}
yy273:
		yych = (char)*++*p;
		switch (yych) {
		case 'C':	goto yy285;
		default:	goto yy26;
		}
yy274:
		yych = (char)*++*p;
		switch (yych) {
		case 'v':	goto yy286;
		default:	goto yy26;
		}
yy275:
		yych = (char)*++*p;
		switch (yych) {
		case 'o':	goto yy287;
		default:	goto yy26;
		}
yy276:
		yych = (char)*++*p;
		switch (yych) {
		case 's':	goto yy288;
		default:	goto yy26;
		}
yy277:
		yych = (char)*++*p;
		switch (yych) {
		case 'i':	goto yy289;
		default:	goto yy69;
		}
yy278:
		yych = (char)*++*p;
		switch (yych) {
		case 'r':	goto yy290;
		default:	goto yy69;
		}
yy279:
		yych = (char)*++*p;
		switch (yych) {
		case 'c':	goto yy228;
		default:	goto yy69;
		}
yy280:
		yych = (char)*++*p;
		switch (yych) {
		case 'h':	goto yy139;
		default:	goto yy69;
		}
yy281:
		yych = (char)*++*p;
		switch (yych) {
		case 'o':	goto yy291;
		default:	goto yy69;
		}
yy282:
		yych = (char)*++*p;
		switch (yych) {
		case 'h':	goto yy292;
		default:	goto yy69;
		}
yy283:
		yych = (char)*++*p;
		switch (yych) {
		case 'e':	goto yy293;
		default:	goto yy69;
		}
yy284:
		yych = (char)*++*p;
		switch (yych) {
		case 'n':	goto yy139;
		default:	goto yy26;
		}
yy285:
		yych = (char)*++*p;
		switch (yych) {
		case 'o':	goto yy294;
		default:	goto yy26;
		}
yy286:
		yych = (char)*++*p;
		switch (yych) {
		case 'e':	goto yy234;
		default:	goto yy26;
		}
yy287:
		yych = (char)*++*p;
		switch (yych) {
		case 'w':	goto yy139;
		default:	goto yy26;
		}
yy288:
		yych = (char)*++*p;
		switch (yych) {
		case 's':	goto yy139;
		default:	goto yy26;
		}
yy289:
		yych = (char)*++*p;
		switch (yych) {
		case 'o':	goto yy295;
		default:	goto yy69;
		}
yy290:
		yych = (char)*++*p;
		switch (yych) {
		case 'C':	goto yy296;
		default:	goto yy69;
		}
yy291:
		yych = (char)*++*p;
		switch (yych) {
		case 'v':	goto yy297;
		default:	goto yy69;
		}
yy292:
		yych = (char)*++*p;
		switch (yych) {
		case 'o':	goto yy298;
		default:	goto yy69;
		}
yy293:
		yych = (char)*++*p;
		switch (yych) {
		case 's':	goto yy299;
		default:	goto yy69;
		}
yy294:
		yych = (char)*++*p;
		switch (yych) {
		case 'd':	goto yy190;
		default:	goto yy26;
		}
yy295:
		yych = (char)*++*p;
		switch (yych) {
		case 'n':	goto yy139;
		default:	goto yy69;
		}
yy296:
		yych = (char)*++*p;
		switch (yych) {
		case 'o':	goto yy300;
		default:	goto yy69;
		}
yy297:
		yych = (char)*++*p;
		switch (yych) {
		case 'e':	goto yy267;
		default:	goto yy69;
		}
yy298:
		yych = (char)*++*p;
		switch (yych) {
		case 'w':	goto yy139;
		default:	goto yy69;
		}
yy299:
		yych = (char)*++*p;
		switch (yych) {
		case 's':	goto yy139;
		default:	goto yy69;
		}
yy300:
		yych = (char)*++*p;
		switch (yych) {
		case 'd':	goto yy240;
		default:	goto yy69;
		}
	}
#line 140 "spock_slaf.c"

    }
}


/* #times substr appears in s, no overlaps */
int 
spock_counter_matchs(const char *s, const char *substr)
{
    int n = 0;
    const char *p = s;

    size_t lenSubstr = strlen(substr);

	    while (*p) 
	    {
	        if (memcmp(p, substr, lenSubstr) == 0) 
	        {
	            ++n;
	            p += lenSubstr;
	        } else 
	            ++p;
	    }

    return n;
}


int 
spock_score_sqli(char *input)
{
	int total_list = 0;
	int score = 0, i = 0;
	
	const char *list[] = 
	{
		"insert","union","where","sleep","delete","mapreduce","timeout","@version","db.injection","/**/","drop"
	};

	total_list = sizeof(list) / sizeof(list[0]);

		while(i!=total_list)
		{
			score+=spock_counter_matchs(input,list[i]);
			i++;
			if(SPOCK_SCORE<=score)
				return score;
		}

	return score;
}

int 
spock_score_pathtraversal(char *input)
{
	int total_list = 0;
	int score = 0, i = 0;
	const char *list[] = 
	{
		"..","\\\\","//","...","shadow","etc","password"
	};

	total_list = sizeof(list) / sizeof(list[0]);

		while(i!=total_list)
		{
			score+=spock_counter_matchs(input,list[i]);
			i++;
				if(SPOCK_SCORE<=score)
					return score;
		}

	return score;
}

int 
spock_score_xss(char *input)
{
	int total_list = 0;
	int score = 0, i = 0;
	const char *list[] = 
	{
		"eval","script","javascript","document","cookie","onstart","onerror","onpageshow","onprogress","alert","onclick","onmouseover","onfinish","fromChar","iframe"
	};

	total_list = sizeof(list) / sizeof(list[0]);

		while(i!=total_list)
		{
			score+=spock_counter_matchs(input,list[i]);
			i++;
				if(SPOCK_SCORE<=score)
					return score;
		}

	return score;
}


int
spock_dfa_check(char *input)
{

	bool match=false;
	char *last = input;


    while(match==false)
			switch (spock_dfa_filter(&input, &last)) 
			{
					case SQLI:
					return 1;
					break;

					case XSS:
					return 2;
					break;

					case PATHTRAVERSAL:
					return 3;
					break;
					  
					case SPOCK_END:
					match=true;	
					break;
			}

	return 0;

}


// jack the ripper function 
// func to split request in chunks, util because a lot functions cannot match request buffer in full mode
bool 
spock_check (char * input)
{
	int option = 0;
	int score = 0;


		option = spock_dfa_check(input);
				switch (option)
				{

						case 1:
						score+=1;
						score+=spock_score_sqli(input);
							if(score >= SPOCK_SCORE)
							{
		        					spock_write_log("Attack type: SQl injection\n");
								return true;
							}
					    	break;

						case 2:
						score+=1;
						score+=spock_score_xss(input);
							if(score >= SPOCK_SCORE)
							{
		        					spock_write_log("Attack type: XSS\n");
								return true;
							}
					   	break;

						case 3:
						score+=1;
						score+=spock_score_pathtraversal(input);
							if(score >= SPOCK_SCORE)
							{
		        					spock_write_log("Attack type: path traversal\n");
								return true;
							}
						break;

				  
				}
				
		
		



	return false;

}


// Deterministic Finite Automata to check if letter exist between a-z or A-Z
// generated by flex+bison
int 
spock_test_letter(char p)
{
	unsigned char yych;

	yych = p;
	switch (yych) 
	{
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
			case 'z':	
				++p;
				return 0;
		default:	
				return 1; 
	}   

}

void 
_CONSTRUCTOR hook_init(void) 
{
	SPOCK_LOAD_CALL(spock_ctx.SSL_read, "SSL_read");
	SPOCK_LOAD_CALL(spock_ctx.SSL_get_rfd, "SSL_get_rfd");
	SPOCK_LOAD_CALL(spock_ctx.SSL_get_wfd, "SSL_get_wfd");
}


void 
_DESTRUCTOR hook_end(void) 
{
	SPOCK_DEBUG("end Spock SLAF");
}



static void *
spock_xmalloc_fatal(size_t size) 
{

	SPOCK_DEBUG("\n Memory FAILURE...\n size dbg: %zu\n",size);

	exit(0);
}


void *
spock_xmalloc (size_t size) 
{
	void *ptr = malloc (size);

		if (ptr == NULL) 
			return spock_xmalloc_fatal(size);

	return ptr;
}


void *
spock_xrealloc(void *ptr, size_t size)
{
	ptr = realloc(ptr, size);

		if (!ptr) 
		{
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

// Fork of OpenBSD's function
void *
spock_xmallocarray(size_t num, size_t size)
{
	void *result = spock_reallocarray(NULL, num, size);

        if (!result) 
        {
            SPOCK_DEBUG("reallocarray failed: %s", strerror(errno));
            exit(0);
        }

	return result;
}


char *
all2lowcase(char *str) 
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


char *
spock_get_ip_str(struct sockaddr *sa, char *s, size_t maxlen)
{
	    switch(sa->sa_family) 
	    {
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

bool 
spock_is_request(char *ptr)
{
		if(ptr == NULL)
			return false;

		if(ptr[0]==' ')
			return false;

		if(ptr[1]==' ')
			return false;

		if(strnlen(ptr,12) < 10)
			return false;

	// So don't use strcmp() or strncmp() at this point. These functions are not thread-safe. Keep it like this:
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

		if ((c = *find++) != '\0') 
		{
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
		"\\xff\\xff",
		"/usr/bin",
		"%s%s%s%s",  // format string...
		"%u%u%u",
		"%x%x%x",
		"%d%d%d",
		"%2e%2e%2f%2e%2e%2f",
		"%252e%252e%252f",
		"%c0%ae",
		"%uff0e%uff0e",
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

	// Test SQL injection/ path traversal/ XSS following  using taint analysis + score based
		if (spock_check(prepared_input)==true)
		{
				free(prepared_input);
				prepared_input=NULL;
				return true;
		}

		while(i!=total_shellcodes)
		{
			if(spock_strnstr(prepared_input, custom_shellcode[i],num))
			{
				free(prepared_input);
				prepared_input=NULL;
				spock_write_log("Attack type: Buffer overflow\n");
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
				spock_write_log("Attack type: Anomaly\n");
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
			int lenmax=(num+128+128)*sizeof(char);
			char *attacker_ip=spock_xmallocarray(129,sizeof(char));
			char *log_line=spock_xmallocarray(lenmax,sizeof(char));
			time_t rawtime = time(NULL);
			struct tm *ptm = localtime(&rawtime);

			spock_burn_mem(attacker_ip,0,128); // save one byte for canary, if you compile with full hardening argvs
			spock_get_ip_str(&addr,attacker_ip,128);	
			spock_burn_mem(log_line,0,lenmax-1);
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


int 
SSL_read(void *ssl, void *buf, int num) 
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


