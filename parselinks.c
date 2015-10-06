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

#include	"util.h"
#include "webfuzzer.h"

#define	FRAME	"frame "
#define  HREF  "href"
#define  SRC   "src"

/**
 ** DESCRIPTION
 ** 	Add hashtable item for each link found in a line from the stream
 ** 	if hostname or ip != NULL then checks if link refers to hostname or ip
 ** 	includes arguments after '?' as query string
 **
 ** RETURN VALUE
 **	The number of links found
 **/
int parse_links( 	const char * line, const char * hostname, 
						const char * ip, char * curdir )
{
	struct linkz	* lk;	

	char	* ptr		= NULL;
	char	* linkn	= NULL;
	char	* query 	= NULL;
	char 	* tfree 	= NULL;
	char	* start	= NULL;

	int	count 	= 0;
	int	proto 	= 0;
	int	match 	= 0;
	int	found		= 0;
	int	updat		= 0;	
	
	if ( line )
		ptr = xstrdup(line);
	else 	
		return 0;

	if ( !ptr )
		return 0;

	tfree = ptr;	
	
	do
	{
		start = ptr ;
	
		if ( (ptr = xstrstr( start, HREF )) )
		{
			ptr += strlen ( HREF );
			NEXTFIELD( ptr );
			found = 1;
		}
		else if ( (ptr = xstrstr( start, FRAME )) )
		{
			if ( (ptr += strlen( FRAME ))
					&& (ptr = xstrstr( ptr, SRC )) )
			{
				if ( (ptr += strlen( SRC )) )	
				{
					NEXTFIELD( ptr );
					found = 1;
				}
			}
		}
		if ( !ISNULL(ptr) && found )
		{
			found = 0;

			if ( !strncasecmp( ptr, "http://", 7 ))
				proto = 7;
			else if ( !strncasecmp( ptr, "javascript:", 11 ))
				continue;
			else if ( !strncasecmp( ptr, "mailto:", 7 ))
				continue; 
			else if ( !strncasecmp( ptr, "news:", 5 ))
				continue;
			else if ( !strncasecmp( ptr, "ftp://", 6 ))
				continue; 
			else if ( !strncasecmp( ptr, "https://", 8 ))
				continue;
					
			if ( proto ) 
			{
				ptr += proto;
				proto = 0;

				if ( hostname )
				{
					if ( !strncasecmp( ptr, hostname, strlen(hostname)) )
						match = 1;
				}
				if ( ip )
				{
					if ( !strncasecmp( ptr, ip, strlen(ip)) )
						match = 1;
				}		
				if ( !match && (hostname || ip) ) 
				{	
					continue;
				}
				else 
				{
					ptr = strchr( ptr, '/' );
					match = 0;
				}
			}
			if ( !ISNULL(ptr) )
			{
				boolean relative = FALSE;
				char	* p = strpbrk( ptr, "#\" '\t\r\n>" ); 

				linkn = ptr;

				if ( p )
				{
					ptr = p + 1;
					*p = 0;
				}

				if ( (query = strchr( linkn, '?')) ) 
					*query++ = 0;
					
				updat = 0;

				if ( !linkn[0] || (linkn[0]=='/' && !linkn[2])  )
					continue;

				if ( strpbrk( linkn, "=<>?&" ) )
					continue;

				if ( !EXT_ISALLOWED( linkn ) )
				{
					debug( "Skipping unallowed file type: %s\n", linkn );
					continue;
				}
				if ( ISRELATIVE( linkn  ) ) 
				{
					relative = TRUE;
					linkn = fix_relative( linkn, curdir );
				}
				if ( (lk = (struct linkz *)hash_get_value( linkn, HTlinks )) )
				{
					if ( !query || ((query) && (lk->flags & LDYNAMIC)) )
						continue;
				}

        		lk = (struct linkz *)xmalloc(sizeof(struct linkz));

				debug( "Link: %s\n", linkn );

				if ( query )
				{
					if ( updat ) 
						lk->flags &= ~LVISITED;

					lk->flags |= LCACHED;
					lk->flags |= LDYNAMIC;
					lk->query = xstrdup( query );
					debug( "Query: %s\n", query );
				}
				
				hash_insert( linkn, lk, HTlinks );
				if ( relative == TRUE ) xfree( linkn );
				updat ^= updat;
				count++ ;
			}
		}
	}
	while( ptr );	

	xfree( tfree );
	return count;
}
