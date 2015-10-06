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
#include "webfuzzer.h"

/**
 **	Finds the value after the equal signs of 'tocatch' key
 **/
static char * catch( const char * string, char * tocatch )
{
   char * tmp = xstrdup( string );
	char * ret = tmp ;

   if ( ret && (ret = xstrstr( ret, tocatch )) )
   {
      if ( (ret = strchr( ret, '=' )) )
      {
			NEXTFIELD( ret );

         if ( ret && *ret )
         {
            TRUNC( ret, " '<>\"\t\r\n" );
				if ( ret && *ret ) 
				{
					ret = xstrdup( ret );
					xfree( tmp );
					return( ret );
				}
         }
      }
   }
	xfree( tmp );
   return NULL;
}

/**
 **	Add nodes to input names list
 **/
static struct formz_item * input_add_node( struct formz_item * fmz, 
												char * name, char * value, t_type type )
{
	struct formz_item * tmp = 
		(struct formz_item *) xmalloc(sizeof(struct formz_item));
	
	if ( value )
		tmp->value = xstrdup( value );
	if ( name )
		tmp->name = xstrdup( name );

	tmp->type = type;
	tmp->next = fmz;
	return tmp;
}

/**
 **	convert string to t_type
 **/
static t_type convert_type( const char * s )
{
	if ( s )
	{
		if( !strcasecmp( s, "text" ) )
			return TEXT;
		if( !strcasecmp( s, "password" ) )
			return PASSWORD;
		if( !strcasecmp( s, "radio" ) )
			return RADIO;
		if( !strcasecmp( s, "checkbox" ) )
			return CHECKBOX; 
		if( !strcasecmp( s, "file" ) )
			return FFILE;
		if( !strcasecmp( s, "hidden" ) )
			return HIDDEN;
	}
	return IGNORED;
}
 
/**
 ** Parses the form if found: 
 **	action
 **	method
 **	input (vars and params)
 **
 ** fills the hashtable 
 ** returns the number of read lines
 **/

#define	STARTFORM_TAG		"<form "
#define	ENDFORM_TAG			"</form>"
#define	STARTINPUT_TAG		"<input "
#define	ENDINPUT_TAG		"</input>"
#define	STARTSELECT_TAG	"<select "
#define	ENDSELECT_TAG		"</select>"
#define	OPTION_TAG			"<option "

void parse_form( 	FILE * stream, const char * line, 
						char * host, char * ip, char * curdir ) 
{
	struct formz	* fk;

	char	* start 	= NULL;
	char 	* method	= NULL;
	char 	* action	= NULL;
	char 	* name	= NULL;
	char 	* value	= NULL;
	char	* type	= NULL;
	char	* vhost	= NULL;

	t_type	t = IGNORED;
	char  	buf[ BUFSIZ ];
	char		* action_link = NULL;

	if ( !stream || !line || !(*line) )
		return;

	strncpy( buf, line, sizeof(buf) );
	buf[ sizeof(buf)-1 ] = 0;

	/**
	 **	FIXME: this can work only if it's all on one line
	 **/
	if ( buf && (start = xstrstr( buf, STARTFORM_TAG )) ) 
	{
		method = catch( start, "method" );
		action = catch( start, "action" );
	}
	if ( !method )
	{
		method = xmalloc( 4 );
		sprintf( method, "get" );
	}
	if ( start && action && *start && *action )
	{
		boolean value_found 			= FALSE;	
		boolean into_select			= FALSE;
		boolean exit 					= FALSE;

		if ( (vhost = url_get_host( action )) )
		{
			if ( strcasecmp( vhost, host ) && strcasecmp( vhost, host ) )
			{
				debug( "Form: host doesn't match\n" );
				xfree( vhost );
				return;
			}
		}

     	if ( !(action_link = url_get_link( action )) )
        	return;

		xfree( action );

     	if ( ISRELATIVE( action_link ) )
        	action = fix_relative( action_link, curdir );
		else
			action = xstrdup( action_link );

		xfree( action_link );

		if ( hash_get( action, HTforms ) )
			return;

		fk = (struct formz *) xmalloc( sizeof(struct formz) );
		debug( "Form method=%s action=%s\n", method, action);

		fk->input = NULL;
		fk->method = xstrdup( method );
		xfree( method );

		while( exit == FALSE )
		{
			char * select = buf;
			char * input = buf;
		
			if ( buf && *buf )
			{
				if ( into_select == FALSE )
				{
					if ( (select = xstrstr( select, STARTSELECT_TAG )) )
					{
						into_select = TRUE;
               	if ( (name = catch( select, "name" )) )
               	{
                 		debug( "Select name=%s\n", name );
               	}
               	select += strlen( STARTSELECT_TAG ) + 1;
					}
				}
				if ( into_select == TRUE )
				{
					if ( (value_found == FALSE) && (select) && 
						  (select = xstrstr( select, OPTION_TAG )) )
					{
						if ( (value = catch( select, "value" )) )
						{
							value_found = TRUE;
							debug( "Select first value=%s\n", value );
						}
						select += strlen( OPTION_TAG );
					}
					if ( xstrstr( buf, ENDSELECT_TAG ) )
					{
						fk->input = input_add_node( fk->input, name, value, SELECT );
						debug( "End Select\n" );
						if ( value_found == TRUE ) xfree( value );
						value_found = FALSE;
						into_select = FALSE;
						xfree( name );
					}
				}
				if ( into_select == FALSE ) do 
				{
					if ( (input = xstrstr( input, STARTINPUT_TAG )) ) 
					{
						type  = catch( input, "type" );
						value = catch( input, "value");
						name  = catch( input, "name" );

						if ( !TYPE_ISALLOWED( (t = convert_type( type )) ) )
						{
							debug( "Input type=\"%s\" ignored\n", type );
						}					
						else if ( name && *name )
						{
							fk->input = input_add_node( fk->input, name, value, t );

							debug( "Input type=\"%s\" name=\"%s\" value=\"%s\"\n",
										type, name, value );

							xfree( name );
							xfree( type );
							xfree( value );		
						}				
						input += strlen( STARTINPUT_TAG );
					}
					if ( input && xstrstr( input, ENDINPUT_TAG ) ) 
						input = NULL;
				}
      		while( input );            
 			
				if ( xstrstr( buf, ENDFORM_TAG ) ) 
				{
					debug( "End of Form\n");
					exit = TRUE;
				} 
				else if ( net_fgets( buf, BUFSIZ, stream ) != NULL ) 
				{
					parse_links( buf, vhost, ip, curdir );
				}
				else	exit = TRUE;
			}
		} 		/* enwhile */		 
	
		hash_insert( action, fk, HTforms );
		xfree( action );
	}
}
