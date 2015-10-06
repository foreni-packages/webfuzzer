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

void	_trunc( char * string, char * delimit )
{
	char * p = strpbrk( string, delimit );

	if ( p ) 
	{
		*p = 0;
	}
}

void * _xmalloc(size_t size, char * function, int line) 
{
	void	* temp = (void *)malloc( size );

	if ( !temp ) {
		fprintf(stderr,"[-] Malloc failed at [%s:%d]\n", function, line);
		exit( EXIT_FAILURE );
	}

	memset( temp, 0, size ); 
	return( temp );
}

char * _xstrdup( const char * s, char * function, int line )
{
	char	* temp  = NULL;

	if ( s )
		temp = (char *)strdup( s );

	if ( !temp ) {
		fprintf(stderr,"[-] Strdup failed at [%s:%d]\n", function, line);
		exit( EXIT_FAILURE );
	}
	return( temp );
}

char * _getdir( const char * p )
{
	char	* path = xstrdup( p );
	char	* c = (char *)xmalloc( 2 );
	
	*c = '/';
	
	if (!path)
		return c;

	if( ISRELATIVE( path ) )
		return c;
	
	if ( (c = strrchr( path, '/' )) && (c + 1) )
		*(c + 1) = 0;

	return( path );
}

char * fix_relative( char * file, char * dir )
{
	char 	* clean 	= NULL;
	char 	* temp	= NULL;
	
	char	* ret		= NULL;

	char 	* c 		= NULL;
	char 	* t 		= NULL;

	int dot = 0,	up = 0;

	if ( !dir || !file )
		return NULL;

	clean = (char *)malloc( strlen(dir) + strlen(file) + 1);
	temp = (char *)malloc( strlen(dir) + strlen(file) + 1);

	sprintf( clean, "%s%s", dir, file );

	/**
	 **	strips out redundant slashes, dot slash and dot dot slash
	 **/
	
	for( c = clean, t = temp; !ISNULL(c) && (t); c++ )
	{
		do
		{	
     		if ( !(up = strncmp( c, "/../", 4 )) )
      	{
				c += 3;
				if ( t > temp ) {
					t -= 1;
         		while ( (t > temp) && *--t != '/' );
				}
      	}
			else if ( !(dot = strncmp( c, "/./", 3 )) )
			{
				c += 2;
			}
		}
		while( !up || !dot ); 
		
      if ( 	((t) && (t - 1)) && (*(t - 1) != '/' || 
				(*(t - 1) == '/' && ( *c != '/' ))) ) 
		{
			*t++ = *c;
		}
	}	

	if ( t ) *t = 0;

	ret = xstrdup( temp );
	xfree( clean );
	xfree( temp );
	return ret;
}

void freport( char * fname, char * fmt, ... )
{
	va_list	ap;	
	FILE		* fp = NULL;	

	if ( !fname || !fmt )
		return;

	if ( !(fp = fopen( fname, "a" )) )
		return;

	va_start( ap, fmt );
	vfprintf( fp, fmt, ap );
	va_end( ap );

	fclose( fp );	
}

/**
 **	case insensitive strstr and strchr
 **/
char * xstrstr( char * ptr, char * pattern )
{

   int   len = 0;
   char  * tmp = ptr;

   if ( !pattern || !ptr )
      return NULL;

   len = strlen(pattern);

   while ( tmp && strncasecmp( tmp, pattern, len ) )
      tmp = (char *)xstrchr( ++tmp, *pattern );

   return tmp;
}

char * xstrchr( char * ptr, int c )
{
		int	chr 	= 0x00;
		char	* t	= NULL;
	
		if ( isupper(c) )
			chr = tolower(c);
		else
			chr = toupper(c);

		for ( t = ptr; (t) && (*t) && (*t != c) && (*t != chr); t++ );

		if ( !(*t) )
			return NULL;
		else
			return t;
}

int xfclose( FILE * stream )
{
	if ( !stream ) {
		return EOF;
	}
	else 
	{
		unsigned long p =  *((long *)(stream));

		if ( !p || p == 0xffffffff )
			return EOF;
	}
	return fclose( stream );
}

int xfileno( FILE * stream )
{
	if ( !stream ) {
		return -1;
	}
	else
	{
		unsigned long p =  *((long *)(stream));
		if ( !p || p == 0xffffffff )
			return -1;
	}
	return fileno( stream );
}
