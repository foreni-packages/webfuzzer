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

#include "util.h"
#include "technic.h"

/**
 **	PROTOTYPES
 **/

static void foutput( struct tofuzz * T, int proto, char * message,
            		char * action, char * url, char * error );

static int match( char * string );

static struct vlist * get_values( const char * query );

static char * make_evil_query_form( struct formz_item * init,
                        struct formz_item * cur, char * teq, char * file );

static char * make_evil_query_link( struct vlist * i, const struct vlist * c,
                        char * teq, char * file );

#define	POST	1
#define	GET	0

static void foutput( struct tofuzz * T, int proto, char * message,
					char * action, char * url, char * error )
{
#	define FMTSTDOUT	GREEN KYA "(" DEF "%s" GREEN KYA ")"	\
			DEF GREEN ": %s " KYA "(" DEF	RED "http://%s%s%c%s" GREEN KYA ")" DEF "\n"

#	define FMTTXT	"(%s): %s (http://%s%s%c%s)\n"

#	define FMTHTML "<p class=\"report\"> <span class=\"proto\"> (%s) </span>\n"	\
						"<span class=\"vuln\"> %s </span>\n"	\
						"<span class=\"url\"> http://%s%s%c%s </span>\n</p>\n\n"

#	define MESSAGE (proto == POST)  ? "POST" : "GET",	\
            message, T->host, ((proto == POST) || action ) ? action : "",	\
				qm, url

	/**
	 **	format is a string like 
	 **		<GET|POST> <possible vuln> <http://host/page?query=bla> [error]
	 **/

	char	qm = ((proto == POST) ? '?' : '/');

	fprintf( stdout, FMTSTDOUT, MESSAGE );

	if ( T->opt->logtype == HTML ) 
		freport( T->opt->logfile, FMTHTML, MESSAGE );
	else
		freport( T->opt->logfile, FMTTXT, MESSAGE );

	if ( error )
	{
		if ( T->opt->logtype == HTML )
			freport( T->opt->logfile, 
						"<div class=\"error\">\n%s\n</div>\n", error );
		else
			freport( T->opt->logfile, "--[ %s ]--\n", error );

		fprintf( stdout, KYA RED "--[ %s ]--\n" DEF, error );
	}  
}

void hack_form( struct tofuzz * T, struct node * p )
{	
	int				count, fd,	ti;

	FILE				* s      = NULL;
	char				* url 	= NULL;
	char  			* action = NULL;
	struct formz 	* fstart	= NULL;
	struct formz 	* fcur	= NULL;
	int      		proto    = GET;
	
	struct formz_item	* cur		= NULL; 
	struct formz_item * start 	= NULL;
	
	unsigned int status 	= 0;

	char	buf[ BUFSIZ ];

	if ( !(p->value) || !(p->key) )
		return;

	action = url_get_link( p->key );

	fstart = (struct formz *)(p->value);
	fcur = fstart;

	if ( !action || !fstart || fstart->flags & FHACKED )
		return;
	else
		fstart->flags |= FHACKED;

	start  = fstart->input;
	cur    = fcur->input;

	fprintf( stdout, KYA "\n -- Checking form: " DEF "%s\n\n", action );

	while( cur )
	{
		if ( cur && cur->name && !strncmp( cur->name, "PHPSESSID", 9 ) ) {
			cur = cur->next;
			continue;
 		}
		if ( cur->type == FFILE ) {
			foutput( T, proto, "Input type = FILE", 
						( proto == POST ) ? action : p->key, cur->name, NULL );
		}
		for( ti = 0; TECHNICS[ ti ].string; ti++ )
		{
			if ( !( T->opt->level & TECHNICS[ ti ].flag ) )
				continue;

			s = NULL;

			fprintf( stdout, RED "* " DEF );

			if ( !strncasecmp( fstart->method, "post", 4 ) )
			{
				proto = POST;
				url = make_evil_query_form( start, cur, TECHNICS[ ti ].string, NULL );
				if ( url ) s = http_request( T, url, action, &status, FALSE );
			}
			else
			{
				proto = GET;
				url = make_evil_query_form( start, cur, TECHNICS[ ti ].string, action );
				if ( url ) s = http_request( T, NULL, url, &status, TRUE );
			}
			if ( s )
			{
      		if ( (fd = xfileno( s )) == -1 )
      		{
         		ERROR( "Can't get file descriptor" );
         		return;
      		}
				if ( status == NOTFOUND || status == NOTALLOW )	
				{
					XCLOSE( fd, s );
					xfree( url );
					xfree( action );
					return;
				}
				else if ( status == INTERR )	
				{
					foutput( T, proto, "Internal server error", 
								action, url, NULL );
				}
				while ( net_fgets( buf, sizeof buf, s ) != NULL )	
				{	
					if ( (count = match( buf )) != -1 )
					{
						TRUNC( buf, "\r\n" );

						if ( count == XSS )
							foutput( T, proto, XSS_MSG, action, url, buf );
						else
							foutput( T, proto, ERRORS[count].toreport, action, url, buf );
					}
           	}
				XCLOSE( fd, s );
        	}
			xfree( url );
		}

		/* we skip checkboxes and radio button, should we ? */

		do {
			cur = cur->next; 
		}
		while ( cur && cur->next && 
				 ( cur->type == RADIO || cur->type == CHECKBOX || 
					!strcasecmp( cur->name, cur->next->name )) );
	}
	xfree( action );
	fprintf( stdout, "\n" );
}

void hack_forms( struct tofuzz * T )
{
	struct node    * p = hash_get_next( HTforms, HTforms[0] );

	while( p )
	{
		hack_form( T, p );
		p = hash_get_next( HTforms, p );
	}
}

void hack_link( struct tofuzz * T, struct node * p )
{
	int				count, fd, ti;

	FILE				* s 		= NULL;
	struct vlist 	* start 	= NULL;
	struct vlist	* cur 	= NULL;
	char				* url		= NULL;
	char				* ext		= NULL;
	char				* user	= NULL;

	char           buf[ BUFSIZ ];

	boolean	cgifound	 		= FALSE;
	unsigned int 	status  	= 0;

	struct	linkz * l = (struct linkz *)(p->value);

	if ( !l  || ( l->flags & LHACKED ) || p->key == NULL )
			return;

	l->flags |= LHACKED;

	/**
	 **	CHECKS FOR CGI
	 **/

	if ( strstr( p->key, CGIDIR ) ) 
	{
		cgifound = TRUE;
	}
	else 
	{	
		ext = url_get_ext( p->key );
		if ( ext ) 
		{
			if ( strstr( CGIEXT, ext ) )
				cgifound = TRUE;
			xfree( ext );
		}
	}

	if ( cgifound == TRUE ) 
	{
		if ( !hash_get( p->key, HTtools) ) 
		{
			hash_insert( p->key, NULL, HTtools );
			foutput( T, GET, "Possible CGI", NULL, p->key, NULL );
		}
	}

	/**
	 **	CHECKS FOR USERNAMES
	 **/

	user = strstr( p->key, USERTAG );
	if ( user )
	{
		user = xstrdup( user );
		TRUNC( user, "%/\t\r\n " );

		if ( !ISNULL(user) && !hash_get( user, HTusers ) ) 
		{
				hash_insert( user, NULL, HTusers );
				snprintf( buf, sizeof buf - 1, "Possible Username: %s", user );
				foutput( T, GET, buf, NULL, p->key, NULL );
		}
		xfree( user );
	}

	if ( !( l->flags & LDYNAMIC ) )
		return;

	start = (cur = get_values( l->query ));
	/**
	 **	CHECKS FOR PARAMS/TECHNICS
	 **/
	fprintf( stdout, KYA "\n -- Checking link: " DEF "%s?%s\n\n", p->key, l->query );

	while ( cur )
	{
		if ( cur && cur->val && !strncasecmp( cur->val, "PHPSESSID", 9 ) ) {
			cur = cur->next;
			continue;
		}
		for( ti = 0; TECHNICS[ ti ].string; ti++ )
		{
			if ( !( T->opt->level & TECHNICS[ ti ].flag ) )
				continue;

			url = make_evil_query_link( start, cur, TECHNICS[ ti ].string, p->key );

			fprintf( stdout, RED "* " DEF );

			if ( (s = http_request( T, NULL, url, &status, TRUE )) )
			{
      		if ( (fd = xfileno( s )) == -1 )
      		{
					ERROR( "Can't get file descriptor" );
         		return;
      		}	
				if ( status == NOTFOUND )
				{
					XCLOSE( fd, s );
					xfree( url );
					return;
				}
				else if ( status == INTERR )	
				{
					foutput( T, GET, "Internal server error", NULL, url, NULL );
				}
				while ( net_fgets( buf, sizeof(buf), s ) != NULL )
				{
					if ( (count = match( buf )) != -1 )
					{
						TRUNC( buf, "\r\n" );

						if ( count == XSS )
							foutput( T, GET, XSS_MSG, NULL, url, buf );
						else
							foutput( T, GET, ERRORS[count].toreport, NULL, url, buf );
					}
				}
				XCLOSE( fd, s );
			}
			xfree( url );
		}
		cur = cur->next;
	}
	fprintf( stdout, "\n" );
}

void hack_links( struct tofuzz * T )
{
	struct node 	* p = hash_get_next( HTlinks, HTlinks[0] );

	while( p )
	{ 
		hack_link( T, p );
		p = hash_get_next( HTlinks, p );
	}
}

/**
 **	FIXME: these all below suck
 **/

static int	match( char * string )
{
	int i;

	if ( !string )
		return -1;

	for( i=0; ERRORS[ i ].tomatch; i++ )
	{
		if( strstr( string, ERRORS[ i ].tomatch ))
		{
			/*
			 *	if we are reading our sent command 
			 *	then we can inject html code probably
			*/

			if ( strstr( string, COMMAND ) )
				return XSS;
			else
				return i;
		}
	}
	return -1;
}

static char * make_evil_query_form(	struct formz_item * init, 
										struct formz_item * cur, 
										char * teq, char * file )
{
	int		w 		= 0 ;
	char		* ret	= NULL;
	
	boolean	rchecked	= FALSE;

	struct	formz_item	* v = init;
	char 		buf[ BUFSIZ ];

	char * tmp = &buf[0];

	memset( buf, 0, sizeof(buf) );

	if ( file ) w += snprintf( tmp, BUFSIZ, "%s?", file );  

	while(  v  )
	{
		if ( w ) tmp += strlen( tmp );

		if ( !v->name  ) v->name 	= DEFAULT_VAL;
		if ( !v->value ) v->value 	= DEFAULT_VAL;

		debug("Make_evil_query_form name=%s value=%s\n", v->name, v->value );

		if ( cur->type == RADIO || cur->type == CHECKBOX )
		{
			return NULL;
		}
		else if ( v->type == RADIO && rchecked == FALSE )
		{
			w += snprintf( tmp, BUFSIZ - w, "%s=1%s", v->name, v->next ? "&" : "" );
			rchecked = TRUE;
		}		
		else if ( (v->type != CHECKBOX) && (v->type != RADIO) && 
					 cur->name && !strcasecmp( cur->name, v->name ) )
		{
			w += snprintf( tmp, BUFSIZ - w, "%s=%s%s", v->name, teq,
								v->next ? "&" : "" );
		}
		else
		{
			w += snprintf( tmp, BUFSIZ - w, "%s=%s%s", v->name, v->value,
			 					v->next ? "&" : "" );
		}
		do v = v->next;
		while( v && v->next && v->name && v->next->name && 
					( v->type == RADIO || v->type == CHECKBOX ||
					!strcasecmp( v->name, v->next->name )) );
	}
	ret = xstrdup( buf );
	return ret;
}

static char * make_evil_query_link( struct vlist * init, 
										const struct vlist * cur, 
										char * teq, char * file )
{
	int	w = 0 ;
	char	* ret ;
	char	* tmp ;
	
	struct 	vlist	* v;
	char		buf[ BUFSIZ ];

	tmp = &buf[0];

	memset( buf, 0, sizeof(buf) );

	w += snprintf( tmp, BUFSIZ, "%s?", file );  

	for( v = init; v; v = v->next )
	{
		tmp += strlen( tmp );

		debug("Make_evil_query_link vval=%s vdef=%s\n", v->val, v->def );

		if ( cur->val && !strcasecmp( cur->val, v->val ) && 
				strncasecmp( cur->val, "PHPSESSID", 9 ) )
		{
			if ( v->next == NULL )
				w += snprintf( tmp, BUFSIZ - w, "%s=%s", v->val, teq );
			else
				w += snprintf( tmp, BUFSIZ - w, "%s=%s&", v->val, teq );
		}
		else
		{
			if ( v->next == NULL )
				w += snprintf( tmp, BUFSIZ - w, "%s=%s", v->val, v->def );
			else
				w += snprintf( tmp, BUFSIZ - w, "%s=%s&", v->val, v->def );
		}
	}
	ret = xstrdup( buf );
	return ret;
}				
	
static struct vlist * vlist_add_node( struct vlist * v, char * val, char * def )
{
	struct vlist	* p = (struct vlist *)xmalloc(sizeof(struct vlist));
	p->val = val ;
	p->def = def ;
	p->next = v;
	return p;
}

static struct vlist * get_values( const char * query )
{
	char				* pv	= NULL;
	char				* tm 	= NULL;
	char				* am 	= NULL;
	char				* eq	= NULL;
	char				* val = NULL;
	char				* def = NULL;
	struct vlist 	* vl 	= NULL;

	tm = xstrdup( query );

	while( (tm) && (eq = strchr( tm, '=' )) )
	{
		*eq = 0;
		val = xstrdup( tm );

		if ( (tm = eq + 1) && (*tm) ) 
		{
			if ( (am = strchr( tm, '&' )) )
			{
				*am = 0; 
				def = xstrdup( tm );
				tm = am + 1;
			}
			else	if ( (pv = strchr( tm, ';' )) )
			{
				*pv = 0;
				def = xstrdup( tm );
				tm = pv + 1;
			}
			else
			{
				def = xstrdup( tm );
				tm = NULL;
			}
		}

		if ( !val ) val = DEFAULT_VAL;
		if ( !def ) def = DEFAULT_VAL;

		vl = vlist_add_node( vl, val, def );
		debug( "vlval=%s vldef=%s\n", vl->val, vl->def );
	}
	return vl;
}
