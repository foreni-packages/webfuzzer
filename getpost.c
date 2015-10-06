/**
 ** This file is part of Webfuzzer
 **	a web site fuzzer for common vulnerabilities
 **
 ** Copyright (C) 2003 gunzip
 **
 ** 	<techieone@softhome.net>
 ** 	<avatar13@iname.com>
 **
 **	http://gunzip.project-hack.org/
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
 ** Foundation, Inc., 59 Temple Place - Suite 330,Boston, MA 02111-1307, USA.
 **
 **/

#include	"util.h"
#include	"webfuzzer.h"

static char * create_client_header( char * host, 
												size_t datalen, 
												boolean cookies )
{
#	define	CRLF		"\r\n"
#	define	HHOST		"Host: "
#	define	HAGENT	"User-Agent: Links (2.1pre9; Linux 2.4.20 i686; 80x30)"
#	define	HACCEPT	"Accept: */*"
#	define	HCONN		"Connection: Close"
#	define	HCHAR		"Accept-Charset: iso-8859-1, utf-8;q=0.5, *;q=0.5"
#	define	HLANG		"Accept-Language: it, en"
#	define	HCONTLEN	"Content-Length: "
#	define	HCTYPE	"Content-Type: application/x-www-form-urlencoded"

	int size = 	strlen(HHOST) + strlen(HAGENT) + strlen(host) + 
					strlen(HACCEPT) + strlen(HCONN) + strlen(HCHAR) + 
					strlen(HLANG) + (cookies ? 4196 : 0 ) + 32;

	char * chead = NULL;

	if ( !host )
		return NULL;

	if ( !datalen )
	{
		chead = xmalloc( size );
	
		sprintf( chead, "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s", 
					HHOST, host, CRLF,
					HAGENT,	CRLF,
					HACCEPT, CRLF,
					HCONN,	CRLF,
					HCHAR,	CRLF,
					HLANG,	CRLF,
					cookies ? cookies_string() : "",
					CRLF );
	}
	else
	{
		chead = xmalloc( size + strlen(HCONTLEN) + strlen(HCTYPE) );
	
		sprintf( chead, "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%d%s%s", 
					HHOST, host, CRLF,
					HAGENT,	CRLF,
					HACCEPT, CRLF,
					HCONN,	CRLF,
					HCHAR,	CRLF,
					HLANG,	CRLF,
					cookies ? cookies_string() : "",
					HCTYPE,	CRLF,
					HCONTLEN, datalen,
					CRLF, CRLF );
	}

	debug( "CLIENT HEADER: %s\n", chead );

	return chead;
}

/** FIXME: anti ids tekniq here **/

static char * xencode( char * url ) 
{
	char 	* ret		= NULL;
	char	* start 	= NULL;

	if ( ISNULL( url ) )
		return NULL;

	start = ret =  xmalloc( strlen(url) * 3 + 1 );
	
	while(  !ISNULL(url) )
	{
		if ( *url == '%' )
		{
			*ret++ = *url;

			if ( !ISNULL(url + 1) && !ISNULL(url + 2) )
			{
				*ret++ = *(++url);
				*ret++ = *(++url);
			}
		}
		else if ( isalnum(*url) || *url == '.' )
		{
				sprintf( ret, "%%%02x", *url );
				ret += 3;
		}
		else	
		{
			*ret++ = *url;
		}
		url++;
	}

	ret = xstrdup( start );
	xfree( start );

	debug( "Line encoded = %s\n", ret );
	return ret;
}

static void get_status( char * resp, unsigned int * status )
{
	char	* ptr = NULL;

	if ( !resp )
		return;

	/* strlen("HTTP/1.x ") = 9 */

	if ( (ptr = resp + 9) )
	{
		switch ( atoi(ptr) )
		{
			case	200:	*status = OK;			break;
			case	301:	*status = MOVED;		break;
			case	302:	*status = FOUND;		break;
			case	400:	*status = BADREQ;		break;
			case	401:	*status = UNAUTH;		break;
			case	403:	*status = FORBID;		break;
			case	404:	*status = NOTFOUND;	break;
			case	405:	*status = NOTALLOW;	break;
			case	414:	*status = TOOLONG;	break;
			case	500:	*status = INTERR;		break;
			default:		*status = OK;
		}
	}
}

/**
 ** DESCRIPTION
 ** 	connects to the httpd 
 **	then send the get or post request for specified page
 **
 ** RETURN VALUE
 **	a pointer to the stream and status information in &status
 **/
static FILE * http_request_r( struct tofuzz * T, 
										char * data, 
										char * page, 
										int * recursion, 
										unsigned int * status,
										boolean encode )
{
	int	fd = 0, sock	= 0;
	char	* sa			= NULL;
	char	* ch 			= NULL;
	char	* header 	= NULL;
	char	* vpage 		= NULL;
	char	* vhost 		= NULL;
	char	* location 	= NULL;
	char	* encoded	= NULL;
	FILE	* stream 	= NULL;

	short	redir = 0;

	if ( !T->host || !page || (*recursion)++ == MAXRECURSION )
		return NULL;

	sock = connect_to_host( T->ip, T->port );
	if ( sock == -1 )
		return NULL;

	if ( data )
		fprintf( stdout, " -- (POST) http://%s%s%s?%s [%c] ",	
					T->host, page[0] == '/' ? "" : "/", page, 
					data, encode ? 'E' : 'N' );
	else
		fprintf( stdout, " -- (GET) http://%s%s%s [%c] ",
				T->host, page[0] == '/' ? "" : "/", page,
				encode ? 'E' : 'N' );

	if ( (stream = fdopen( sock, "a+" )) == NULL )
	{
		ERROR( "Can't create stream" );
		return NULL;
	}
   if ( (fd = fileno( stream )) == -1 )
	{
		ERROR( "Can't get file descriptor" );
      return NULL;
	}

	if ( encode == TRUE ) 
		encoded = xencode( page );

	if ( !net_fprintf( stream, "%s%s%s HTTP/1.0\r\n", 
			data ? "POST" : "GET",
			page[0] == '/' ? " " : " /", encoded ? encoded : page ) )
	{
		ERROR( "Can't send query" );
		return NULL;
	}

	if ( encode == TRUE ) 
		xfree( encoded );

	if ( !net_fprintf( stream, "%s", 
			ch = create_client_header( T->host, data ? strlen(data) : 0, 
												T->opt->cookies )) )
	{
		xfree( ch );
		ERROR( "Can't send client header" );
		return NULL;
	}
	if ( data )
	{
		if  ( !net_fprintf( stream, "%s\r\n", data ) )
		{
			ERROR( "Can't post data" );
			return NULL;
		}
	}	
	if ( !(header = get_header( stream )) )
	{
		ERROR( "Can't get header from server" );
		return NULL;
	}
	if ( (sa = get_server_answer( header )) )
	{
		if ( status ) 
			get_status( sa, status );

		fprintf( stdout, KYA "(" DEF "%s" KYA ")\n" DEF, sa );
	}

	if ( T->opt->cookies ) 
		get_cookies( header );

	if ( (location = redirect_get_location( header )) )
	{
		vpage = url_get_link( location );
		vhost = url_get_host( location );
		T->port = url_get_port( location ); 
			
		if ( vhost && strcmp( vhost, T->host ) )
			T->host = xstrdup( vhost );

		if ( vpage )
		{
			if ( ISRELATIVE( vpage ) )
			{
				char tmp[ BUFSIZ ]; 
				char * dir = GETDIR(page);
				if ( dir )
				{
					snprintf( tmp, sizeof tmp - 1, "%s%s", dir, vpage ); 
					xfree( vpage );
					vpage = xstrdup( tmp );
					debug( "Redirecting (relative) to %s:%d %s\n", T->host, T->port, vpage );
					xfree( dir );
				}
			}
			else
			{
				debug( "Redirecting to %s:%d %s\n", T->host, T->port, vpage );
			}
			redir = 1;
		}
		else
		{
			ERROR( "Redirect failed\n" );
			redir = -1;
		}
	}

	xfree( ch );
	xfree( sa );
	xfree( header );
	xfree( location );

	if ( redir == 1 )
	{
		XCLOSE( fd, stream );

		if ( (T->ip = resolve( T->host )) != -1 )
			return( http_request_r( T, data, vpage, recursion, status, encode ));
		else
			redir = -1;
	}

	xfree( vhost );
	xfree( vpage );

	if ( redir != -1 ) 
		return stream;
	else 
		return NULL;
}

FILE * http_request( struct tofuzz * T, char * data, char * page,
							unsigned int * status, boolean encode )
{
	int first = 0;
	return http_request_r( T, data, page, &first, status, encode );
}

char * http_head_request( struct tofuzz * T )
{
	int sockfd	= 0;
	FILE * s 	= NULL;

	if ( (sockfd = connect_to_host( T->ip, T->port )) != -1 )
	{
		if ( (s = fdopen( sockfd, "a+" )) == NULL )
		{
			ERROR( "Can't create stream" );
			return NULL;
		}
		if ( net_fprintf( s, "HEAD / HTTP/1.0\r\n\r\n" ) != -1 )
			return get_header( s );
	}
	XCLOSE( sockfd, s );
	return NULL;
}
