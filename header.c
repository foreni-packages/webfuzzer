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

/**
 **	Looks for httpd server header (to implement)
 **/

#include "util.h"
#include "webfuzzer.h"

#define	MAXFIELDS	24

/**
 ** DESCRIPTION
 **	gets the http header 
 **
 ** RETURN VALUE
 **	the stream after the header
 **/
char * get_header( FILE * stream )
{
	int 	nfields	= 0;
	char	buf[ BUFSIZ / MAXFIELDS ];	
	char	tmp[ BUFSIZ ];

	memset( tmp, 0, sizeof(tmp) );

	while ( net_fgets( buf, sizeof(buf), stream ) != NULL )
	{
		if ( 	( ++nfields == MAXFIELDS ) ||
				( buf[0] == '\n' ) || ( buf[0] == '\r' ) )
			break;
		else
			strcat( tmp, buf );
	}

	if  ( ISNULL(tmp) ) 
		return NULL;

	return ( xstrdup( tmp ) );
}

char	* get_server_answer( char * header )
{
	char 	* tmp 	= NULL;
	char	* ret 	= NULL;
	char	* start 	= NULL;

	if ( ISNULL(header) )
		return NULL;

	if ( (start = tmp = xstrdup( header )) )
	{
		while( tmp && *tmp != '\r' && *tmp != '\n' )
			tmp++;
		*tmp = 0;
		ret = xstrdup( start );
		xfree( start );
	}
	return ret;		
}

/**
 **	checks for redirect and returns location value
 **/
char * redirect_get_location( const char * header )
{
	char	* ret = NULL ;
	char	* ptr = NULL ;
   char  * tmp = NULL ;

	if ( ISNULL( header ) ) 
		return NULL;	

	if ( (tmp = xstrdup( header )) )
		ptr = strstr( tmp, "Location: " );

	if ( ptr )
	{
		ptr += strlen( "Location: " );
		NEXTFIELD( ptr );
		if ( ptr )
		{
			TRUNC( ptr, " \t\r\n" );
			if ( *ptr ) ret = xstrdup(ptr);
		}
	}
	xfree( tmp );
	return ret;
}

char * url_get_proto( const char * url )
{
	char	* ret = NULL;
	char	* tmp = NULL;
	char	* ptr = NULL;

	if ( ISNULL(url) )
		return NULL;

	if ( (tmp = xstrdup( url )) )
		while( !isalpha( ptr++ ) );

	if ( (ret = strstr( ptr, "://" )) )
	{
		*ret = 0;
		ret = xstrdup( ptr );
	}
	xfree( tmp );
 	return ret;
}

char * url_get_host( const char * url )
{
	char	* ret = NULL;
	char	* tmp = NULL;
	char	* ptr = NULL;

	if ( ISNULL(url) )
		return NULL;

	if ( (tmp = xstrdup( url )) )
		ptr = strstr( tmp, "://" );

	if ( ptr )
	{
		char	* slash = NULL;
		char	* colon = NULL;

		ptr += strlen( "://" );

		if ( ptr )
			slash = strchr( ptr, '/' );

		if ( slash )
			*slash = 0;

		colon = strchr( ptr, ':' );

		if ( colon )
		{
			*colon = 0;
			debug( "URL host: %s\n", ptr );
		}

		ret = xstrdup(ptr);
	}
	xfree( tmp );
	return ret;
}

char * url_get_ext( char * url )
{
   char  * ret 	= NULL;
   char	* point 	= NULL;
	char 	* slash 	= NULL;

	if ( ISNULL(url) )
		return NULL;

	point = strrchr( url, '.' );
	slash = strrchr( url, '/' );

	if ( point && slash && point > slash )
		ret = point + 1;

	if ( !ISNULL(ret) ) 
		return xstrdup( ret );
	else 
   	return NULL;
}

char * url_get_file( char * url )
{
	char	* ret = NULL;

	if ( (ret = strrchr( url, '/' )) )
		if ( ++ret ) ret = xstrdup( ret );
	
	return ret;
}

char * url_get_link( const char * url )
{
	char	* ret = NULL;
   char 	* tmp = NULL;
	char 	* ptr = NULL;

	if ( ISNULL(url) )
		return NULL;

	if ( (tmp = xstrdup( url )) )
		ptr = strstr( tmp, "://" );

	if ( ptr ) 
	{
		ptr += strlen( "://" );

		if ( ptr ) 
			ptr = strchr( ptr, '/' );

		if ( !ptr )
		{
			xfree( tmp );
			ret = xstrdup("/");
			return( ret );
		}
	}
	else
	{
		ptr = tmp ;
		NEXTFIELD( ptr );
	}
	if ( ptr )
	{
		TRUNC( ptr, " \t\r\n" );
		debug( "URL link: %s\n", ptr );
		ret = xstrdup(ptr);
	}

	xfree( tmp );
	return ret;
}

unsigned short url_get_port( const char * url )
{
	char  * tmp = NULL;
   char 	* ptr = NULL;
   unsigned short port = 80;

	if ( ISNULL(url) )
		return port;

	if ( (tmp = xstrdup( url )) )
		ptr = strstr( tmp, "://" );

   if ( ptr )
   {
      char * slash = NULL;
      ptr += strlen( "://" );
      if ( ptr )
			slash = strchr( ptr, '/' );
      if ( slash )
      {
         char * colon;
         *slash = 0;
         colon = strchr( ptr, ':' );
         if ( colon++ )
         {
				port = (unsigned short)atoi( colon );
            debug( "URL port: %s\n", ptr );
         }
      }
   }
	xfree( tmp );
	return port;
}

#define REFRESH	"refresh"
#define URLTAG		"url"

char * get_refresh( char * line )
{
	char	* ret = NULL;
	char 	* ptr = NULL;
	char	* tmp = NULL;

	if ( ISNULL(line) )
		return NULL;

	if ( (tmp = ptr = xstrdup(line)) && (ptr = xstrstr( ptr, REFRESH )) )
	{
		if ( (ptr = xstrstr( ptr, URLTAG )) )
		{
			if ( (ptr += strlen(URLTAG)) )
			{
				NEXTFIELD( ptr );

				if ( ptr ) TRUNC( ptr, "\"' >\r\n");
				if ( !ISNULL(ptr) ) ret = xstrdup( ptr );
			}
		}
		xfree( tmp );
	}
	return( ret );
}
