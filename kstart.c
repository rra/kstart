/*
 * $Source$
 * $Author$ 
 *
 * Copyright 1987, 1988 by the Massachusetts Institute of Technology. 
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>. 
 *
 * Routine to initialize user to Kerberos.  Prompts optionally for
 * user, instance and realm.  Authenticates user and gets a ticket
 * for the Kerberos ticket-granting service for future use. 
 *
 * Options are: 
 *
 *   -i[instance]
 *   -r[realm]
 *   -v[erbose]
 *   -l[ifetime]
 *   -p/-s get pw from stdin
 *   -u[ser]
 *   -f [srvtab file] 
 *   -S[service name]
 *   -I[service instance]
 *   -t[get AFS token]
 */

#ifndef	lint
static char rcsid_kinit_c[] =
"$Id$";
#endif	lint

#include <mit-copyright.h>
#include <stdio.h>
#include <pwd.h>
#include <krb.h>


#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#ifdef NEED_SYS_FCNTL_H
#include <sys/fcntl.h>
#endif

#ifdef USE_UNISTD_H
#include <unistd.h>
#endif

#ifndef ORGANIZATION
#define ORGANIZATION "Stanford University (Leland)"
#endif /*ORGANIZATION*/

#ifdef	PC
#define	LEN	64		/* just guessing */
#endif /*	PC */

#ifdef __svr4__
/* just to get MAXHOSTNAMELEN */
#include <netdb.h>
#endif
#ifdef	BSD42
#include <string.h>
#include <sys/param.h>
#if 	defined(ultrix) || defined(sun) || defined(__SCO__)
#define LEN	64
#else
#define	LEN	MAXHOSTNAMELEN
#endif	/* defined(ultrix) || defined(sun) */
#endif	/* BSD42 */

#if !defined(LEN) 
#define LEN 255
#endif

#if defined(DO_AKLOG) && !defined(AKLOG_PROGRAM)
#define AKLOG_PROGRAM	"/usr/leland/bin/aklog" 
#endif

#ifdef SHORT_LIFETIME
#define	LIFE	DEFAULT_TKT_LIFE	/* lifetime of ticket in 5-minute units */
#else
#define LIFE    141
#endif

#define SNAME "krbtgt"
#define SINST realm

extern char *optarg;
extern int optind,opterr;
extern int krb_debug;

char   *progname;

void
get_input(s, size, stream)
char *s;
int size;
FILE *stream;
{
	char *p;

	if (fgets(s, size, stream) == NULL)
	  exit(1);
	if ( (p = strchr(s, '\n')) != NULL)
		*p = '\0';
}

int main(argc, argv)
    int     argc;
    char   *argv[];
{
    char    aname[ANAME_SZ];
    char    inst[INST_SZ];
    char    realm[REALM_SZ];
    char    sname[SNAME_SZ];
    char    sinst[INST_SZ];
    char    srvtab[MAXPATHLEN + 1] ; 
    char    buf[LEN];
    char   *username = NULL;
    int     iflag, rflag, vflag, lflag, lifetime, k_errno;
    int     tflag;
    int     sflag;
    int     qflag;
    int     nflag;
    int     fflag;
    char    *the_kinit_prog;
    int     c;
    register char *cp;
    register i;

    *inst = *realm = *sname = *sinst = '\0';
    iflag = rflag = vflag = lflag = 0;
    tflag = 0;
    sflag = 0;
    qflag = 0;
    nflag = 0;
    fflag = 0; 
    the_kinit_prog = NULL;
    lifetime = LIFE;
    progname = (cp = strrchr(*argv, '/')) ? cp + 1 : *argv;

    opterr=1;

    while ((c = getopt(argc,argv,"dspqtnvu:i:r:S:I:l:f:h:")) != EOF) 
      switch (c) {
      case 'l': if ( (lifetime=atoi(optarg)) <0) usage();  break;
      case 'p':
      case 's': 
	++sflag; 
	if ( fflag != 0 ) { 
	  printf("%s: cannot use both -s and -f flags\n",
		 progname);
	  usage;
	}
	break;
      case 'q': ++qflag;                                   break;
      case 't': ++tflag;                                   break;
      case 'n': ++nflag;                                   break;
      case 'd': ++krb_debug;                               break;
      case 'u': username = optarg;                         break;
      case 'f': 
	++fflag ;
	if (strlen(optarg) < sizeof(srvtab)) {
	  strcpy(srvtab, optarg);
	} else {
	  printf("%s: instance '%s' too long (%d max)\n",
		 progname, optarg, sizeof(srvtab));
	  usage;
	}
	if ( sflag != 0 ) { 
	  printf("%s: cannot use both -s and -f flags\n",
		 progname);
	  usage;
	} 
	break;
      case 'i': 
	if (strlen(optarg) < sizeof(inst)) {
	  strcpy(inst, optarg);
	} else {
	  printf("%s: instance '%s' too long (%d max)\n",
		 progname, optarg, sizeof(inst));
	  usage;
	}
	break;
      case 'r':
	if (strlen(optarg) < sizeof(realm)) {
	  strcpy(realm, optarg);
	} else {
	  printf("%s: realm '%s' too long (%d max)\n",
		 progname, optarg, sizeof(realm));
	  usage;
	}
	break;
      case 'S':
	if (strlen(optarg) < sizeof(sname)) {
	  strcpy(sname, optarg);
	} else {
	  printf("%s: service name '%s' too long (%d max)\n",
		 progname, optarg, sizeof(sname));
	  usage;
	}
	break;
      case 'I':
	if (strlen(optarg) < sizeof(sinst)) {
	  strcpy(sinst, optarg);
	} else {
	  printf("%s: service instance '%s' too long (%d max)\n",
		 progname, optarg, sizeof(sinst));
	  usage;
	}
	break;
      default: usage();
      }
	argv = &argv[optind];
	if (*argv) {
	  if (username) {
	    usage();
	  } else {
	    username = *argv;
	  }
	}

	the_kinit_prog =  (char *)getenv("KINIT_PROG");

	if (the_kinit_prog==NULL) {
	  the_kinit_prog = AKLOG_PROGRAM;
	} else {
	  tflag=1;
	}

	if (username==NULL) {
	  struct passwd *pw;
	  pw = getpwuid(getuid());
	  if (pw) { username = pw->pw_name; }
	}
	if (username &&
	    (k_errno = kname_parse(aname, inst, realm, username))
	    != KSUCCESS) {
	  fprintf(stderr, "%s: %s\n", progname, krb_err_txt[k_errno]);
	  iflag = rflag = 1;
	  username = NULL;
	}
	if (k_gethostname(buf, LEN)) {
	  fprintf(stderr, "%s: k_gethostname failed\n", progname);
	  exit(1);
	}
	if (!qflag) {
	  char *s=(char *)getenv("SESSION_ENCRYPTED"); 
	  char *w=(char *)getenv("SESSION_CHECK");
	  if (s==NULL) {
	    if(w) {
	      if (strcmp(w,"warn")==NULL) {
		fprintf(stderr,"warning: session may not be encrypted\n");
	      } else if (strcmp(w,"error")==NULL) {
		fprintf(stderr,"error: session is not encrypted!\n");
		exit(0);
	      }
	    }
	  } else {
	    fprintf(stderr,"session is encrypted with %s\n",s);
	  }
	}
	if (!qflag) printf("%s (%s)\n", ORGANIZATION, buf);
	if (username && !qflag) {
	  printf("Kerberos Initialization for \"%s", aname);
	  if (*inst)
	    printf(".%s", inst);
	  if (*realm)
	    printf("@%s", realm);
	  printf("\"");
	  if (*sname) {
	    printf(" for service \"%s", sname);
	    if (*sinst)
	      printf(".%s", sinst);
	    printf("\"");
	  }
	  printf("\n");
	}

	if (lifetime < 5)
	  lifetime = 1;
	else
#ifdef SHORT_LIFETIME
	  lifetime /= 5;
#else
	lifetime = krb_time_to_life(0,lifetime*60);
#endif
	/* This should be changed if the maximum ticket lifetime */
	/* changes */
	if (lifetime > 255)
	  lifetime = 255;

	if (!*realm && krb_get_lrealm(realm, 1)) {
	  fprintf(stderr, "%s: krb_get_lrealm failed\n", progname);
	  exit(1);
	}
	if (!*sname)
	  strcpy(sname, "krbtgt");
	if (!*sinst)
	  strcpy(sinst, realm);
	if (sflag) { 
	  char pp[132];
	  if (! qflag ) printf("Password: "); 
	  get_input(pp,sizeof(pp), stdin);
	  k_errno = krb_get_pw_in_tkt(aname, inst, realm, sname, sinst,
				      lifetime, pp);
	} else if ( fflag ) {  
	  k_errno = krb_get_svc_in_tkt(aname , inst, realm,
				       sname, realm, lifetime, srvtab);
	} else { 
	  k_errno = krb_get_pw_in_tkt(aname, inst, realm, sname, sinst,
				      lifetime, 0);
	}
	if (vflag) {
	  printf("Kerberos realm %s:\n", realm);
	  printf("%s\n", krb_err_txt[k_errno]);
	} else if (k_errno) {
	  fprintf(stderr, "%s: %s\n", progname, krb_err_txt[k_errno]);
	  exit(1);
	}
#ifdef DO_AKLOG
	if (tflag && !nflag) {
	  if (! access( the_kinit_prog, X_OK)) 
	    (void) system(the_kinit_prog);
	}
#endif
	return 0;
      }

usage()
{
    fprintf(stderr, "Usage: %s [options] [name]\n", progname);
    fprintf(stderr,"   -u <client principal> (default local username)\n");
    fprintf(stderr,"   -i <client instance> (default null)\n");
    fprintf(stderr,"   -S <service name> (default krbtgt)\n");
    fprintf(stderr,"   -I <service instance> (default realm name)\n");
    fprintf(stderr,"   -r <service realm>\n");
    fprintf(stderr,"   -v[erbose]\n");
    fprintf(stderr,"   -l n  (ticket lifetime in minutes)\n");
    fprintf(stderr,"   -s  read password from stdin\n");
    fprintf(stderr,"   -q  quiet\n");
#ifdef DO_AKLOG
    fprintf(stderr,"   -t  get AFS token via aklog or KINIT_PROG\n");
    fprintf(stderr,"   -n  don't run KINIT_PROG\n");
    fprintf(stderr,"\n");
 fprintf(stderr,"  If the environment variable KINIT_PROG is set to a program (such as aklog)\n");
 fprintf(stderr,"  then this program will automatically be executed after the ticket granting\n");
 fprintf(stderr,"  ticket has been retrieved.\n");
    fprintf(stderr,"\n");

#endif
    exit(1);
}
