/**
 ** This file is part of Webfuzzer
 **	a web site fuzzer for common vulnerabilities
 **
 ** Copyright (C) 2003 gunzip 
 ** <techieone@softhome.net>, <avatar13@iname.com>
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>

#ifdef DEBUG
static __inline__ void debug( char * fmt, ... )
{
	va_list  ap;
	va_start( ap, fmt );
	fprintf( stdout, "[!] ");
	vfprintf( stdout, fmt, ap );
	va_end( ap );
	fflush( stdout );
}
#else
#	define debug(fmt...)
#endif

#define NEXTFIELD( ptr )                    		\
while ( (ptr) && (*ptr) && !isalnum(*ptr)       	\
&& (*ptr) != '/' && (*ptr) != '.'               	\
&& (*ptr) != '~' && (*ptr) != '#'			\
&& (*ptr) != 0x22 && (*ptr) != 0x27 ) (ptr)++;		\
if ( (ptr) && ((*ptr) == 0x22 || (*ptr) == 0x27) )	\
(ptr)++;
		
#define ISRELATIVE( ptr ) ((*ptr == '/') ? 0 : 1)

#define	TRUNC( a, b ) _trunc( (a), (b) )

#define ERROR( x ) fprintf( stdout, "\n\n -- (ERROR) %s::%s\n\n", __FUNCTION__, (x) ); 

#define ISNULL(x) (!(x) || !(*(x)))

#define GETDIR( ptr ) _getdir( (ptr) )

#define XCLOSE( fd, fp ) close(fd); xfclose(fp);

#define xmalloc( a ) _xmalloc((a), __FUNCTION__, __LINE__)

#define	xfree( x ) if( x ) free( x )

#define xstrdup( s ) _xstrdup( (s), __FUNCTION__, __LINE__)

void  _trunc( char * string, char * delimit );

void * _xmalloc(size_t size, char *function, int line);

char * _xstrdup( const char * s, char * function, int line );

char * xtolower( char * s );

char * _getdir( const char * p );

char * fix_relative( char * file, char * dir );

void freport( char * fname, char * fmt, ... );

char * xstrstr( char * ptr, char * pattern );

char * xstrchr( char * ptr, int c );

int xfclose( FILE * stream );

int xfileno( FILE * stream );
