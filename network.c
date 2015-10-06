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
 **	All functions return -1 on error
 **/
#include "util.h"

#include <stdarg.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>

#define TIMEOUT		0xA

#ifndef INADDR_NONE
#define INADDR_NONE	0xffffffff
#endif

#ifndef INADDR_ANY
#define INADDR_ANY	0x00000000
#endif

unsigned long resolve( char * host )
{
	unsigned long 	rev ;
	struct hostent 	* he ;

	if ( !host ) 
	{
		ERROR( "Null hostname" );
		return -1;
	}
	if (( rev = inet_addr( host )) != INADDR_NONE ) 
	{	
		return rev ;	
	}
	if ( (he = gethostbyname( host )) == NULL )  
	{
		ERROR( host );
		return -1;
	}
	else
	{
		return ((struct in_addr *)(he->h_addr))->s_addr ;
	}
}

int connect_to_host( unsigned long ip, unsigned short port )
{
	
	int ret, flags, s ;
	struct  sockaddr_in server ;

	memset( &server, 0x0, sizeof(server) );

	server.sin_port = htons ( port );
	server.sin_family = AF_INET ;
	server.sin_addr.s_addr = ip ;

	if ((s = socket(AF_INET, SOCK_STREAM, 0)) == -1 ) {
		ERROR( "socket" );
		return -1 ;
	}

	/**
	 ** sets non blocking socket and connects, ripped somewhere (teso cose ?)
	 **/

	if ((flags = fcntl (s, F_GETFL, 0)) == -1 ) {
		close( s );
		return -1;
	}

	if (fcntl(s, F_SETFL, flags | O_NONBLOCK) == -1) {
		close( s );
		return -1;
	}

	ret = connect(s, (struct sockaddr *)&server, sizeof(server));

	if ( ret < 0 )
	{
		if ( errno != EINPROGRESS ) {
			close( s );
			return -1;
		}
		else
		{
			int                     n ;
			struct timeval          tv = { TIMEOUT, 0 };
			fd_set                  rset, wset;

			FD_ZERO( &rset );
         FD_ZERO( &wset );
         FD_SET( s, &rset );
         FD_SET( s, &wset );

         if ((n = select( s + 1, &rset, &wset, NULL, &tv)) == -1 ) {
				ERROR( "socket" );
				return -1;
			}
			/** 
		 	 ** handles timeout 
			 **/
         if (n == 0) {
         	close( s );
            ERROR( "timeout" );
				return -1;
        	}

       	if (FD_ISSET( s, &rset ) || FD_ISSET( s, &wset ))
       	{
       		int error = 0 ;
        		int len = sizeof( error );
        		if (getsockopt(s, SOL_SOCKET, SO_ERROR, &error, &len) == -1) {
					ERROR( "getsockopt" );
					return -1;
        		}
        		if (error != 0) {
					debug("[*] SO_ERROR != 0\n"); 
					return -1;
				}
			}
			else
			{
				return -1 ;
			}
		}
	}

	/**
	 **	restores flags and returns
	 **/
	if ( fcntl(s, F_SETFL, flags) == -1 )
		return -1;
	else 
		return s;
}

int net_fprintf( FILE * stream, const char * format, ...)
{
	struct timeval	tv = { TIMEOUT, 0 };
	fd_set	wfds ;
	int		ret ;
	int		fd ;

	if ( !stream )
		return -1;

	fflush( stream );

	if ( (fd = xfileno( stream )) == -1 )
	{
		ERROR( "fileno" );
		return -1;
	}
	FD_ZERO( &wfds );
	FD_SET( fd, &wfds );

	if ( (ret = select( fd + 1, NULL, &wfds, NULL, &tv )) == -1 ) {
		ERROR( "select" );
		return -1;
	}
	if ( ret == 0 ) {
		close( fd );
		ERROR( "timeout" );
		return -1;
	}
	
	if ( FD_ISSET( fd, &wfds ) ) 
	{
		int		n = 0;	
		va_list		ap;

		va_start( ap, format );
		n += vfprintf( stream, format, ap );
		va_end( ap );
		return n;
	}	
	else
	{
		ERROR( "error writing data to the stream" );
		return -1;
	}
}

char * net_fgets( char * s, int size, FILE * stream )
{
	struct timeval  	tv = { TIMEOUT, 0 };
	fd_set				rfds ;
	int					ret ;
	int					fd ;

	if ( !stream || *((long *)(stream)) == 0xffffffff )
		return NULL;

	fflush( stream );

	memset( s, 0, size );

	if ( (fd = xfileno( stream )) == -1 )
	{
		return NULL;
	}

	FD_ZERO( &rfds );
	FD_SET( fd, &rfds );

	if ( (ret = select( fd + 1, &rfds, NULL, NULL, &tv )) == -1 ) 
	{
		ERROR( "select" );
		return NULL;
	}
	if ( ret == 0 ) 
	{
		close( fd );
		ERROR( "timeout" );
		return NULL;
	}
	if ( FD_ISSET( fd, &rfds ) )
	{
		return( fgets( s, size, stream ) );
	}
	else
	{
		ERROR( "error receiving data from stream" );
		return NULL;
	}
}

char * ip_to_ascii( unsigned long ip )
{
	struct in_addr ia ;

	ia.s_addr = ip ;
	return inet_ntoa( ia );
}
