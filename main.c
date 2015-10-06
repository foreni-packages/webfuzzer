#include "util.h"
#include "webfuzzer.h"

#include <time.h>
#include <signal.h>

#define	GET	'G'
#define	POST	'P'

/** this global variable needed in the signal handler **/

static char * __htmllog = NULL;

void sigexit_handler( int sig )
{
	fprintf( stdout, DEF );
	fprintf( stderr, DEF );

	if ( __htmllog )
		freport( __htmllog, "\n</body>\n</html>\n\n" );

	signal( SIGINT, SIG_DFL );
	raise( SIGINT );
}

void usage( char * arg )
{
	fprintf( stdout, 	"\n__Usage: %s -G|-P URL [OPTIONS]\n\n"
						
							"\t-G <url>\tget this as starting url (with parameters)\n"
							"\t-P <url>\tpost this as starting url (with parameters)\n"
							"\t-x\t\thtml output (txt default)\n"
							"\t-c\t\tuse cookies\n"
							"\t-C <cookies>\tset this cookie(s) **\n\n"

							"\t-s\tcheck for sql, asp, vb, php errors (default)\n"
							"\t-d\tcheck for directory traversal *\n"
							"\t-p\tcheck for insecure perl open or xss *\n"
							"\t-e\tcheck for execution through shell escapes or xss *\n"
							"\t-a\tset all of the above switches on *\n\n"

							"* very noisy scan which works against UNIX systems only\n"	
							"** cookies are in the form \"name1=value1 name2=value2\"\n\n", arg );
}

int main( int argc, char * argv[] )
{
	time_t			now;
	int				fd	= 0;					/* file descriptor 		*/
	int				opt	= 0;				/*	command line options	*/
	int 				count	= 0;
	unsigned int	status	= 0;
	boolean			allvisited	= FALSE;
	boolean			refresh	= FALSE;
	struct node 	* htnode	= NULL;
	char 				* page	= NULL;
	char				* data	= NULL;
	char				* header	= NULL;
	char				* newurl	= NULL;
	char				* dir	= NULL;			/* current directory		*/
	FILE 				* stream	= NULL;
	char				buf[ BUFSIZ ];
	char				method = GET;

	struct tofuzz	* target = xmalloc( sizeof(struct tofuzz) );

	target->opt = xmalloc( sizeof(struct options) );

	if ( !target || !target->opt )
	{
		ERROR("Not enough memory");
		return -1;
	}	

	time( &now );

	signal( SIGINT, sigexit_handler );
	
	puts( BANNER );

	if ( argc < 3 )
	{
		usage( argv[0] );
		return -1;
	}

	/* default settings */

	target->host = NULL;
	target->port = 80;
	target->ip = -1;
	target->opt->level = 0;
	target->opt->logfile = NULL;
	target->opt->logtype = TXT;
	target->opt->os = 0;
	target->opt->cookies = FALSE;

	/* parse command line */

	while ( (opt = getopt(argc, argv,"G:P:cC:o:xsdpeah")) !=EOF )
	{
		switch( opt )
		{
			case	'G':
			case	'P':
				target->host = url_get_host( optarg );
				if ( !target->host )
					target->host = xstrdup( optarg );
				else
				{
      			target->port = url_get_port( optarg );
      			page = url_get_link( optarg );
      			dir = GETDIR( page );
				}
				method = opt;
				break;
			case	'c':
				target->opt->cookies = TRUE;
				break;
			case	'C':
				target->opt->cookies = TRUE;
				get_cookies_opt( optarg );
				break;
/*
 *	TODO
 *			case 'w':
 *				target->opt->os = WINDOWS;	
 *				break;
*/
			case 'x':
				target->opt->logtype = HTML;
				break;
			case 'o': 
				target->opt->logfile = xstrdup( optarg ); 
				break;
			case 's': 
				target->opt->level |= TFSAP; 
				break;
			case 'd': 
				target->opt->level |= TFDIR; 
				break;
			case 'p': 
				target->opt->level |= TFPERL; 
				break;
			case 'e': 
				target->opt->level |= TFSHELL; 
				break;	
			case 'a': 
				target->opt->level = ( TFSAP | TFDIR | TFPERL | TFSHELL ); 
				break;
			case 'h':
			default:	
				usage(argv[0]); 
				return -1;
		}
	}

	if ( !target->host )
	{
		fprintf( stderr, "You should use at leat one between -G or -P options\n" );
		return -1;
	}

	if ( !target->opt->logfile ) 
	{
			target->opt->logfile = xmalloc( strlen(target->host) + 8 ); 
			if ( target->opt->logtype == TXT )
				sprintf( target->opt->logfile, "%s.txt", target->host );
			else	if ( target->opt->logtype == HTML ) 
			{
				sprintf( target->opt->logfile, "%s.html", target->host );
				__htmllog = target->opt->logfile;
			}
	}

	/* default settings */

	if ( !target->opt->level )
		target->opt->level |= TFSAP;
/*
 *	if ( !target->opt->os )
 *		target->opt->os = UNIX;
*/

	if ( !page )
		page = xstrdup( DEFAULTPAGE );

	if ( !dir )
		dir = GETDIR( DEFAULTPAGE );

	debug("Curdir: %s page=%s\n", dir, page );

	/* initializes hash tables */

	for ( count = HT_SIZE - 1; count; count-- )
	{
		HTlinks[count] = NULL;
		HTforms[count] = NULL;
		HTtools[count] = NULL;
		HTusers[count] = NULL;
		HTcookies[count] = NULL;
	}

	fflush( stdout );

	if ( (target->ip = resolve( target->host )) == -1 )
	{
		ERROR( "Can't resolve host" );
		exit( EXIT_FAILURE );
	}

	memset( buf, 0, sizeof buf );

	if ( target->opt->logtype == HTML )
	{	
		freport( target->opt->logfile, "<html>\n"
					"<head><title> Scan of %s </title>\n"
					"<link rel=\"stylesheet\" href=\"style.css\" type=\"text/css\" title=\"default\">"
					"</head>\n\n<body>\n<h1>Webfuzzer log</h1>\n\n"
					"<ul>\n<li>host %s</li>\n<li>port %d</li>\n<li>start page %s</li>" 
					"<li>ip %s</li>\n<li>date %s</li></ul>\n\n", 
					target->host, target->host, target->port, page, ip_to_ascii( target->ip ), ctime( &now ));
	}

	snprintf( buf, sizeof buf - 2,
			"\n-------------------------------------------------------------------------\n" 
			" Scan of %s:%d [%s] (%s)\n %s" 
			"-------------------------------------------------------------------------\n\n", 
			target->host, target->port, page, ip_to_ascii( target->ip ), ctime( &now ));

	if ( target->opt->logtype == TXT )
		freport( target->opt->logfile, "%s", buf );

	fprintf( stdout, "%s", buf );

	if ( (header = http_head_request( target )) == NULL )
	{
		ERROR( "Can't get server version" );
	}
	else
	{
		fprintf( stdout, RED "Server header:\n\n" DEF "%s\n\n", header );

		if ( target->opt->logtype == HTML )
			freport( target->opt->logfile, "<h2>Server header</h2>\n"
						"<pre><p class=\"header\">%s</p></pre>\n<h2>Report</h2>\n", header );
			else
				freport( target->opt->logfile, "Server header:\n\n%s\n\n", header );

		xfree( header );
	}

	if ( method == POST )
	{
		data = strchr( page, '?' );
		if ( data )
			*data++ = 0;	
	}

	do
	{
		refresh = FALSE;

		stream = http_request( target, data, page, NULL, FALSE );

		if ( stream == NULL )
		{
			ERROR( "Can't get start page" );
			return -1;
		}
		if ( (fd = xfileno( stream )) == -1 )
		{
			ERROR( "Can't get file descriptor" );
      	return -1;
		}
		while ( net_fgets( buf, sizeof buf, stream ) != NULL ) 
		{
			if ( (newurl = get_refresh( buf )) )
			{
				char * vhost = url_get_host( newurl );
				char * vpage = url_get_link( newurl );

				target->port	= 	url_get_port( newurl );

				refresh 	= 	TRUE;

				if ( vhost ) 
				{
					xfree( target->host );
					target->host = xstrdup( vhost ); 
					xfree( vhost );
				}
				if ( vpage ) 
				{ 
					xfree( page ); 
					page = xstrdup( vpage ); 
					xfree( vpage );
				}
				if ( (target->ip = resolve( target->host )) == -1 )
				{
					ERROR( "Can't resolve refresh host" );
					return -1;
				}
				xfree( newurl );
			}
			parse_links( buf, target->host, ip_to_ascii( target->ip ), dir );
			parse_form( stream, buf, target->host, ip_to_ascii( target->ip ), dir );
		}
		XCLOSE( fd, stream );
	}
	while( refresh == TRUE && count++ < MAXRECURSION );

	xfree( page );

	do
	{
		allvisited = TRUE;

		for( htnode = hash_get_next( HTlinks, HTlinks[0] ); htnode ; htnode = hash_get_next( HTlinks, htnode ) )
		{
			struct linkz * l = (struct linkz *)(htnode->value);
			if ( !(l->flags & LVISITED) )
			{
				allvisited = FALSE;
				l->flags |= LVISITED;
				if ( (stream = http_request( target, NULL, htnode->key, &status, FALSE )) ) ;
				{
					if ( (fd = xfileno( stream )) == -1 )
      			{
						ERROR( "Can't get file descriptor" );
						return -1;
      			}
					if ( status == NOTFOUND )
					{
						XCLOSE( fd, stream );
						continue;
					}
      			while ( net_fgets( buf, sizeof buf, stream ) != NULL )
      			{
						xfree( dir );
						dir = GETDIR( htnode->key );
         			parse_links( buf, target->host, ip_to_ascii( target->ip ), dir );
         			parse_form( stream, buf, target->host, ip_to_ascii( target->ip ), dir );
      			}
					XCLOSE( fd, stream );
   			}
			}
			hack_forms( target );
			hack_link( target, htnode );
		}
	}
	while( allvisited == FALSE );

	hack_forms( target );
	hack_links( target );

	fprintf( stdout, DEF "\n\n -- End of Scan\n");

	if ( target->opt->logtype == HTML )
		freport( target->opt->logfile, "\n</body></html>\n" );
	
	return 1;
}
