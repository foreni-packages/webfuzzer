/**
 ** This file is part of Webfuzzer
 **	a web site fuzzer for common vulnerabilities
 **
 ** Copyright (C) 2003 gunzip 
 **
 **   <techieone@softhome.net>
 **   <avatar13@iname.com>
 **
 **   http://gunzip.project-hack.org/
 **
 ** This program is free software; you can redistribute it and/or
 ** modify it under the terms of the GNU General Public License
 ** as published by the Free Software Foundation; either version 2
 ** of the License, or (at your option) any later version.
 **
 ** This program is distributed in the hope that it will be useful,
 ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 ** GNU General Public License for more details.
 **
 ** You should have received a copy of the GNU General Public License
 ** along with this program; if not, write to the Free Software
 ** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 **
 **/

#include "hash.h"

/**
 **     GLOBAL HASHTABLES
 **/
struct node * HTlinks[ HT_SIZE ];
struct node * HTforms[ HT_SIZE ];
struct node * HTusers[ HT_SIZE ];
struct node * HTtools[ HT_SIZE ];
struct node * HTcookies[ HT_SIZE ];

#define	VERSION	"0.2.0"
#define	BANNER	GREEN "Webfuzzer " DEF VERSION " (c) gunzip"

typedef enum { FALSE = 00, TRUE = 01 } boolean;

struct	error	{
	char	* tomatch;
	char	* toreport;
};

#define	TFSAP		1
#define	TFPERL		2
#define	TFSHELL		4
#define	TFDIR		8	

struct options {
	int	level;
	boolean	cookies;
	char	* logfile;
	enum	{ HTML, TXT } logtype;
	enum	{ UNIX, WINDOWS } os;
};

struct tofuzz {
	char	* host;
	unsigned long	ip;
	unsigned short	port;
	struct options	* opt;
};	

struct  technic   {
        char    * string;
        unsigned int flag;
};

#ifdef COLORS
#	define	DEF	"\033[0m"
#	define	KYA	"\033[1m"
#	define	GREEN	"\033[32m"
#	define	RED	"\033[31m"
#	define	BLUE	"\033[36m"
#else
#	define DEF
#	define KYA
#	define GREEN
#	define RED
#	define BLUE
#endif

#define DEFAULTPAGE	"/"
#define CGIDIR		"cgi-bin"
#define CGIEXT		".exe .cgi"
#define	USERTAG		"~"

static char * allowed_ext[]= 
{
	"cgi"	,	"html"	, 
	"htm"	, 	"asp"	, 
	"php"	, 	"shtml"	, 
	"php3"	,	"php4"	,
	"txt"	, 	"jsp"	, 
	"pl"	,	"phtml" ,
	"xhtml"	,	NULL
};

#define	EXT_ISALLOWED( l )	_ext_isallowed( l )
#define	TYPE_ISALLOWED( t )	_type_isallowed( t )

#define MAXRECURSION 3

#define MAXARGS 24

#define	LCACHED		0x1
#define	LVISITED	0x2
#define	LDYNAMIC	0x4
#define	LHACKED		0x8	

#define FHACKED		0x1

#define  OK       	0x1
#define  MOVED    	0x2
#define  FOUND    	0x3
#define  BADREQ   	0x4
#define  UNAUTH   	0x5
#define  FORBID   	0x6
#define  NOTFOUND 	0x7
#define  NOTALLOW 	0x8
#define  TOOLONG  	0x9
#define  INTERR   	0xA

struct vlist {
   char		* val;
   char		* def;
   struct vlist	* next;
};

/**
 ** 	Target ( = link ) is the key in the hashtable
 **/
struct  linkz  {
	unsigned long	flags;
	char    	* query;
};

/**
 **     Types marked with C = checked, with U = unused (to implement)
 **/
typedef enum    {
		SELECT,
		TEXT,
		PASSWORD,
/*C*/		CHECKBOX,
/*C*/		RADIO,
/*U*/		SUBMIT,
/*U*/		RESET,
		FFILE,
		HIDDEN,
/*U*/		IGNORED,
/*U*/		IMAGE,
/*U*/		BUTTON  }       t_type;


/**
 **	Action ( = link ) is the key in the hastable
 **/
struct  formz_item {
	t_type			type;
	char			* name;
	char			* value;
	struct formz_item	* next;
};

struct	formz	{
	char			* method;
	struct formz_item	* input;
	unsigned long		flags;
}; 

static __inline__ int _ext_isallowed( const char * l )
{
	int		i ;
	const char 	* p ;

	if ( !l ) return 0;

	for ( p = l; p && *p; p++ );

	if ( *(p - 1) == '/' ) return 1;

        p = strrchr( l, '.' );

	if((p) && (++p)) {
		for( i = 0; allowed_ext[ i ]; i++ ) {
			if ( !strcmp( p, allowed_ext[ i ] ) )
				return 1;
		}
		return 0;
	}
	return 1;
}

static __inline__ int _type_isallowed( t_type t )
{
	switch( t )	
	{
		case	IGNORED:
		case	SUBMIT:
		case	RESET:
		case	IMAGE:
		case	BUTTON:	
				return 0;
		default:
				return 1;
	}
	return -1;
}

/**
 **	parselinks.h
 **/
int parse_links( const char * line, const char * hostname,  
		const char * ip, char * curdir );

/**
 **	parseform.c
 **/
void parse_form( FILE * stream, const char * line, char * host, char * ip, char * curdir );

/**
 **	getpost.c
 **/
FILE * http_request( struct tofuzz * T, char * data, char * page, 	
		unsigned int * status, boolean e );

char * http_head_request( struct tofuzz * T );

/**
 **	network.c
 **/
unsigned long resolve( char * host );

int connect_to_host( unsigned long ip, unsigned short port );

int net_fprintf( FILE * stream, const char * format, ...);

char * net_fgets( char * s, int size, FILE * stream );

char * ip_to_ascii( unsigned long ip );

/**
 **	header.c
 **/
char * get_header( FILE * stream );

char * get_server_answer( char * header );

char * redirect_get_location( const char * header );

char * url_get_proto( const char * url );

char * url_get_host( const char * url );

char * url_get_link( const char * url );

char * url_get_file( char * url );

char * url_get_ext( char * url );

unsigned short url_get_port( const char * url );

char * get_refresh( char * line );

/**
 **	webfuzzer.c
 **/
void hack_link( struct tofuzz * T, struct node * p );

void hack_links( struct tofuzz * T );

void hack_form( struct tofuzz * T, struct node * p );

void hack_forms( struct tofuzz * T );

/**
 **	cookies.c
 **/
int get_cookies( const char * header );

int get_cookies_opt( const char * args );

char * cookies_string( void );

