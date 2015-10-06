/**
 **	SERVER
 **		Set-Cookie: name=value; domain=.domain.com; 
 **			path=/; expires=DDD, DD-MMM-YYYY 00:00:00 GMT
 **
 **	CLIENT
 ** 		Cookie: foo=bar
 **
 **/

#include "util.h"
#include "webfuzzer.h"

/* FIXME: we ignore path */

#define COOKIE_HEADER_LEN	12

/* strlen( "set-cookie: " ); */

#define	COOKIE_HEADER	"set-cookie: "

#define	COOKIE	"Cookie: "

/*	Maximun cookie header length is 4K */

#define	MAXCOOKIESIZE	1024 * 4

int
get_cookies( const char * header )
{
	char	* ptr;
	char	* tofree;

	unsigned count = 0;

	if ( !header )
		return 0;

	tofree = ptr = xstrdup( header );

	/* reads from server */

	while ( (ptr = xstrstr( ptr, COOKIE_HEADER )) )
	{
		if ( !ISNULL(ptr) )
		{	
			/* put cookie string in hashtable */

			ptr += COOKIE_HEADER_LEN;

			if ( !ISNULL(ptr) )
			{
				while ( !ISNULL(ptr) && isspace(*ptr) )
					ptr++ ;

				if ( !ISNULL(ptr) )
				{
					char	* name = ptr;
					char	* value = strchr( ptr, '=' );

					if ( value && value > ptr )
					{
						*value++ = 0;

						ptr = value;

						if ( !ISNULL(value) )
            		{
               		while( !ISNULL(ptr) && !isspace(*ptr) && *ptr != ';' )
                  		ptr++;

               		if ( !ISNULL(ptr) )
                  		*ptr++ = 0;

							hash_insert( name, xstrdup( value ), HTcookies );
						}
						else
							hash_insert( name, NULL, HTcookies );

						count++;

						debug( "Cookie: name=%s value=%s\n", name, value );
					}
				}	
			}
		}
	}
	xfree( tofree );

	return count;
}

int
get_cookies_opt( const char * args )
{
	char	* ptr;
	char	* tofree;

	unsigned count	= 0;

	if ( !args )
		return 0;

	tofree = ptr = xstrdup( args );

	while( !ISNULL(ptr) )
	{	
		while ( !ISNULL(ptr) && isspace(*ptr) )
			ptr++;

		if ( !ISNULL(ptr) )
		{
			char	* name = ptr;
			char	* value = strchr( ptr, '=' );

			if ( value && value > ptr )
			{
				*value++ = 0;
			
				ptr = value;

				if ( !ISNULL(value) )
				{
					while( !ISNULL(ptr) && !isspace(*ptr) )
						ptr++;

					if ( !ISNULL(ptr) ) 
						*ptr++ = 0;

					hash_insert( name, xstrdup(value), HTcookies );
				}
				else
				{
					hash_insert( name, NULL, HTcookies );
				}
				count++;

				debug( "Cookie: name=%s value=%s\n", name, value );
			}
		}
	}
	xfree( tofree );

	return count;
}

char * 
cookies_string( void )
{	
	struct node	* p;
	char	ret[ MAXCOOKIESIZE ];

	memset( ret, 0, sizeof ret );

	p = HTcookies[0];

	if ( p )
		snprintf( &ret[ strlen(ret) ], sizeof ret - 1, "Cookie: %s=%s\r\n", p->key, 
					 p->value != NULL ? (char *) p->value : "" );

	while( (p = hash_get_next( HTcookies, p )) )
	{
			int len = strlen( ret );
			snprintf( &ret[ len ], sizeof ret - len, "Cookie: %s=%s\r\n", p->key,
				p->value ? (char *) p->value : "" );
	}

	debug( "Cookie header:\n%s", ret );

	return xstrdup( ret );
}
