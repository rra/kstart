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
 *   -f [keytab file] 
 *   -S[service name]
 *   -I[service instance]
 *   -t[get AFS token]
 */

#include "config.h"

#ifndef	lint
static char rcsid_kinit_c[] =
"$Id$";
#endif	lint

#include <mit-copyright.h>
#include <stdio.h>
#include <pwd.h>
#include <krb5.h>


#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <unistd.h>

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
/* Solaris 2.5.x groks this */ 
#include <string.h> 
#if !defined(LEN) 
#define LEN 255
#endif

#if defined(DO_AKLOG) && !defined(PATH_AKLOG)
#define PATH_AKLOG	"/usr/pubsw/bin/aklog" 
#endif

#ifdef DO_AKLOG
# include <sys/wait.h> 
# define KSTART_CANT_ACCESS_PROG 7
#endif

#ifdef SHORT_LIFETIME
#define	LIFE	DEFAULT_TKT_LIFE	/* lifetime of ticket in 5-minute units */
#else
#define LIFE    3600
#endif
#define FUDGE_FACTOR 113   /* To make sure ticket updates BEFORE it expires */ 

#define SNAME "krbtgt"
#define SINST realm

/* Only Solaris and IRIX have this. */
#ifndef MAXNAMELEN
# define MAXNAMELEN 512
#endif

extern char *optarg;
extern int optind,opterr;

int kstart_debug = 0 ; 

char   *progname;

void usage() ; 

void
get_input(s, size, stream)
char *s;
int size;
FILE *stream;
{
	char *p;

	if (fgets(s, size, stream) == NULL)
	  exit(1);
	if ( (p = (char *)strchr(s, '\n')) != NULL)
		*p = '\0';
}

krb5_error_code
KRB5_CALLCONV
kinit_prompter(
    krb5_context ctx,
    void *data,
    const char *name,
    const char *banner,
    int num_prompts,
    krb5_prompt prompts[]
    )
{
    int i;
    krb5_prompt_type *types;
    krb5_error_code rc =
	krb5_prompter_posix(ctx, data, name, banner, num_prompts, prompts);
    return rc;
}


int main(argc, argv)
    int     argc;
    char   *argv[];
{
    /* Should really fix these to be more K5 like */ 
    char    aname[MAXNAMELEN]; /* Got to pick something */ 
    char    inst[MAXNAMELEN];
    char    realm[MAXNAMELEN];
    char    sname[MAXNAMELEN];
    char    sinst[MAXNAMELEN];
    char    service_name[MAXNAMELEN]; 
    char    keytab[MAXPATHLEN + 1] ; 
    char    ticket_file[MAXPATHLEN + 1] ; 
    char    env_tkfile[MAXPATHLEN + 11] ; 
    char    buf[LEN];
    char   *username = NULL;
    int     iflag, rflag, vflag, lflag, lifetime, k5_errno;
    int     tflag;
    int     sflag;
    int     qflag;
    int     nflag;
    int     fflag;
    int     kflag; 
    int     keep_ticket;
    int     happy_ticket; 
    char    *the_kinit_prog;
    int     prog_status = 0 ; /* the status returned by system(the_kinit_prog) */ 
    int     c;
    register char *cp;
    register i;
  
    krb5_context ctx; 
    krb5_ccache  ccache; 
    krb5_principal k5_me; 
    krb5_creds my_creds; 
    krb5_get_init_creds_opt options; 
    krb5_keytab k5_keytab ; 
    krb5_deltat    life_secs,starttime ; 
    
    keytab[0] = '\0' ; 
    *inst = *realm = *sname = *sinst = '\0';
    iflag = rflag = vflag = lflag = 0;
    tflag = 0;
    sflag = 0;
    qflag = 0;
    nflag = 0;
    fflag = 0; 
    kflag = 0; 
    keep_ticket = 0 ; 
    happy_ticket = 0 ; 
    the_kinit_prog = NULL;
    lifetime = LIFE;
    progname = (cp = (char *)strrchr(*argv, '/')) ? cp + 1 : *argv;

    opterr=1;

    while ((c = getopt(argc,argv,"dspqtnvu:i:r:S:I:l:f:K:k:H:")) != EOF) 
	switch (c) {
	case 'l':     /* Lifetime */ 

	    k5_errno = krb5_string_to_deltat(optarg, &life_secs);
	    if (k5_errno != 0 || life_secs == 0) {
		com_err(progname,k5_errno, "Bad lifetime value %s: Use 10h 10m format\n", optarg);
		usage();
	    }
	    lifetime = life_secs/60 ; 
	    break;
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
	case 'v': ++vflag;                                   break;
	case 'n': ++nflag;                                   break;
	case 'd': ++kstart_debug;                               break;
	case 'u': username = optarg;                         break;
	    /*Stayin' Alive, uh, uh, uh, stayin' aliveeeee ! */ 
	case 'K': keep_ticket = atoi(optarg);                break;
	    /* Like -K but checks at beginning and exits if okay */ 
	case 'H': happy_ticket = atoi(optarg);               break; 
	case 'k': 
	    ++kflag ;
	    if (strlen(optarg) < sizeof(ticket_file)) {
		strcpy(ticket_file, optarg);
	    } else {
		printf("%s: ticket file '%s' too long (%d max)\n",
		       progname, optarg, sizeof(ticket_file));
		usage;
	    }
	    break ; 
	case 'f': 
	    ++fflag ;
	    if (strlen(optarg) < sizeof(keytab)) {
		strcpy(keytab, optarg);
	    } else {
		printf("%s: keytab '%s' too long (%d max)\n",
		       progname, optarg, sizeof(keytab));
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
    if ( keep_ticket > 0 && fflag == 0 ) { 
	printf("%s: Keep ticket option -K requires -f option\n",progname) ; 
	usage; 
    }
    if ( keep_ticket > lifetime ) { 
	printf("%s: keep_ticket %d > lifetime %d\n",progname,keep_ticket,lifetime); 
	usage; 
    }
    the_kinit_prog =  (char *)getenv("KINIT_PROG");

    if (the_kinit_prog==NULL) {
	the_kinit_prog = PATH_AKLOG;
    } 
/* This is probably the wrong thing to do in k5start. */
/* We should not run the_kinit_prog unless told to    */  
/*     else { */
/* 	tflag=1; */
/*     } */

    if (username==NULL) {
	struct passwd *pw;
	pw = getpwuid(getuid());
	if (pw) { username = pw->pw_name; }
    }
    /* Get K5 context */ 

  
    if (k5_errno = krb5_init_context(&ctx)) {
	com_err(progname, k5_errno, "while initializing Kerberos 5 library");
	return 0;
    }



    /* Set ticket cache */ 
    if ( kflag ) { 
	k5_errno = krb5_cc_resolve(ctx,ticket_file,&ccache); 
	/* put ticket_file into env so the_kinit_prog will see it. */  
	sprintf(env_tkfile,"KRB5CCACHE=%s",ticket_file);
	putenv(env_tkfile); 
    } else { 
	if ((k5_errno = krb5_cc_default(ctx, &ccache))) {
	    com_err(progname, k5_errno, "while getting default ccache");
	    return 0;
	}
    }
    if ( keep_ticket || happy_ticket) { 
	if ( ! vflag ) qflag++ ;
    }

    /* Add inst to username, should really just require full principal name on cmd line. */ 
    if ( inst[0] != '\0' ) { 
	i = strlen(inst) + strlen(username) + 5 ; 
	cp = (char * ) malloc( i); 
	sprintf(cp,"%s/%s",username,inst);
	username = cp ; 
    } 
    if (username &&
	(k5_errno = krb5_parse_name(ctx, username,&k5_me))
	!= 0) {
	com_err( progname, k5_errno, "when parsing %s", username);
	iflag = rflag = 1;
	username = NULL;
    }

    if ( gethostname(buf, LEN)) {
	fprintf(stderr, "%s: gethostname failed\n", progname);
	exit(1);
    }

    if (!qflag) {
	char *s=(char *)getenv("SESSION_ENCRYPTED"); 
	char *w=(char *)getenv("SESSION_CHECK");
	if (s==NULL) {
	    if(w) {
		if (strcmp(w,"warn")== 0 ) {
		    fprintf(stderr,"warning: session may not be encrypted\n");
		} else if (strcmp(w,"error")== 0) {
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
	/* There is a memory leak here if username was malloc'd in inst loop above */ 
	if ((k5_errno = krb5_unparse_name(ctx,k5_me,&username))) { 
	    com_err(progname, k5_errno, "when unparsing name %s",username);
	    return 0;
	}
	printf("Kerberos Initialization for \"%s", username);
    
	printf("\"");
	if (*sname) {
	    printf(" for service \"%s", sname);
	    if (*sinst)
		printf(".%s", sinst);
	    printf("\"");
	}
	printf("\n");
    }


    if (!*realm ) {
	strncpy(realm,krb5_princ_realm(ctx,k5_me)->data,sizeof(realm));
	if ( realm == NULL ) { 
	    fprintf(stderr, "%s: krb5_princ_lrealm failed\n", progname);
	    exit(1);
	}
    }
    if (!*sname)
	strcpy(sname, "krbtgt");
    if (!*sinst)
	strcpy(sinst, realm);
    if (strlen(sname) + strlen(sinst) + 2 > sizeof(service_name)) {
        fprintf(stderr, "%s: principal name too long\n", progname);
        exit(1);
    }
    sprintf(service_name,"%s/%s",sname,sinst); 
    service_name[MAXNAMELEN-1] = '\0';

    /* if we have a valid service ticket exit */ 
    if ( happy_ticket ) { 
	if ( ! ticket_expired(ctx,ccache,k5_me,sname,sinst,realm,happy_ticket) ) {
	    exit(0); 
	}
    }

    /* Need to init creds,service_name and options. */ 
    life_secs = lifetime* 60; 
    krb5_get_init_creds_opt_set_tkt_life(&options, life_secs);
KEEP_ALIVE: 
    starttime = 0 ; /* Might want to twiddle this later */ 
    if (sflag) { 
	char pp[132];
	if (! qflag ) printf("Password: "); 
	get_input(pp,sizeof(pp), stdin);
	k5_errno = krb5_get_init_creds_password(ctx,&my_creds,k5_me,
					       pp,kinit_prompter,0,
					       starttime,service_name,&options);
    } else if ( fflag ) {  

	k5_errno = krb5_kt_resolve(ctx, keytab, &k5_keytab);
	if (k5_errno != 0) {
	    com_err(progname, k5_errno, "resolving keytab %s", 
		    keytab);
	    exit(1);
	}
	k5_errno = krb5_get_init_creds_keytab(ctx,&my_creds,k5_me,
					     k5_keytab,
					     starttime,service_name,&options);

    } else { 
	k5_errno = krb5_get_init_creds_password(ctx,&my_creds,k5_me,
					      0,kinit_prompter,0,
					      starttime,service_name,&options);

    }

    if ( k5_errno ) { 
	com_err(progname, k5_errno, "when getting initial creds"); 
    } 

    if (k5_errno = krb5_cc_initialize(ctx, ccache, k5_me)) {
	com_err(progname, k5_errno, "when initializing cache");
	goto cleanup;
    }

    if (k5_errno = krb5_cc_store_cred(ctx, ccache, &my_creds)) {
	com_err(progname, k5_errno, "while storing credentials");
	goto cleanup;
    }


cleanup:
    if (my_creds.client == k5_me) {
	my_creds.client = 0;
    }

    krb5_free_cred_contents(ctx, &my_creds);
    if (keytab[0] && k5_keytab != NULL )
	krb5_kt_close(ctx, k5_keytab);
    if ( k5_errno ) { 
	exit(k5_errno); 
    }

#ifdef DO_AKLOG
    if (tflag && !nflag) {
	if (! access( the_kinit_prog, X_OK)) {
	    /* IRIX 6.5 doesn't like calling WEXITSTATUS() directly on the return
	       value of system(). */
	    prog_status = system(the_kinit_prog);
	    prog_status = WEXITSTATUS(prog_status);
      
	    if ( vflag ) { 
		printf("%s exited with status %d\n",the_kinit_prog,prog_status); 
	    }
	} else { 
	    prog_status = KSTART_CANT_ACCESS_PROG ; 
	}
    }
#endif
    if  ( keep_ticket > 0 ) { 
	for(;;) { 
	    sleep(keep_ticket*60) ; 
	    if ( ticket_expired(ctx,ccache,k5_me,sname,sinst,realm,keep_ticket) ) { 
		goto KEEP_ALIVE ; 
	    }
	}

    } else { 
	exit(prog_status);
    }
}

/* Stolen from appl/bsd/rlogin.c */ 
int 
ticket_expired(krb5_context ctx, 
	       krb5_ccache ccache,
	       krb5_principal k5_me,
	       char *service,char *inst, char *realm, int check ) { 
    krb5_creds *v5creds = 0; 
    krb5_creds increds, *outcreds = NULL ; 
    krb5_principal k5service ;

    int rem = 1;
    int lifetime,len_rlm,len_sn ; 
    int now,then ; 

    memset((char *) &increds, 0, sizeof(increds));
    

    len_rlm = strlen(realm); 
    if (rem = krb5_build_principal(ctx,
				   &k5service, 
				   len_rlm,
				   realm,
				   service,
				   inst,
				   NULL)) {
	com_err(progname, rem,
		"while creating service principal name");
	return rem ; 
    }

    increds.client = k5_me;
    increds.server = k5service;
    
    rem = krb5_get_credentials(ctx,0,ccache, &increds,&outcreds);
    
    now = time(0); 
    
    if (rem == 0) {              
	then = outcreds->times.endtime ; 
	if ( then < ( now + 60*check + FUDGE_FACTOR)) { 
	    rem = KRB5KRB_AP_ERR_TKT_EXPIRED;
	}
    }
    
    if ( k5service != NULL ) { 
	krb5_free_principal(ctx,k5service);
    } 
    if ( outcreds != NULL ) { 
	krb5_free_creds(ctx,outcreds);
    }
    
    return rem ; 

} 

void
usage()
{
    fprintf(stderr, "Usage: %s [options] [name]\n", progname);
    fprintf(stderr,"   -u <client principal> (default local username)\n");
    fprintf(stderr,"   -i <client instance> (default null)\n");
    fprintf(stderr,"   -S <service name> (default krbtgt)\n");
    fprintf(stderr,"   -I <service instance> (default realm name)\n");
    fprintf(stderr,"   -r <service realm>\n");
    fprintf(stderr,"   -v[erbose]\n");
    fprintf(stderr,"   -l lifetime (i.e. 10 hours)\n");
    fprintf(stderr,"   -K n  (check and renew tgt every n minutes, implies -q unless -v)\n"); 
    fprintf(stderr,"   -k <ticket_file>  use ticket_file as ticket cache\n"); 
    fprintf(stderr,"   -H n (Check for happy tgt, i.e. doesn't expire in less than n minutes, if Happy exit with status 0, otherwise try and get a tgt)\n"); 
    fprintf(stderr,"   -s  read password from stdin\n");
    fprintf(stderr,"   -f <keytab> read password from svrtab file\n");
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
