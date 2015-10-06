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
 **	Poor man string hashtable implementation
 **/

#include "util.h"
#include "hash.h"

/**
 ** DESCRIPTION
 ** 	Inserts an item in the hashtable
 ** 	Updates item if already exists
 **
 ** RETURN VALUES:
 ** 	1	on success
 ** 	0 	if key already exists
 **	-1 on error
 **
 */ 
int hash_insert( const char *	key, void * value, struct node ** hashtable )
{
	struct node *	p;
	unsigned long hash;

	if ( !key )
		return -1;

	hash = get_hash( key );
	p = hashtable[ hash ];

	while( p ) 
	{
		if ( !strcasecmp( key, p->key ) )
		{
			p->value = value;				/* update item		*/
			return 0;				 		/*	if already in 	*/
		}	
		p = p->next;									
	}

	p = (struct node *)xmalloc( sizeof(struct node) );

	p->key = xstrdup( key );
	p->value = value;
	p->next = hashtable[ hash ];
	hashtable[ hash ] = p;
	
	return 1;
}

/**
 ** DESCRIPTION
 **	Searches for a key in the hashtable 
 **
 ** RETURN VALUES
 ** 	The pointer to the item if found
 **	NULL if not found
 **/
struct node * hash_get( const char * key, struct node ** hashtable )
{
	struct node	*	p;
	unsigned long 	hash;

	if ( !key )
		return NULL;

	hash = get_hash( key );
	p = hashtable[ hash ];

	for ( p = hashtable[ hash ]; p ; p = p->next ) 
	{
		if ( !strcasecmp( key, p->key ) )
		{
			return p;
		}
	}
	return NULL;
}

/**
 **	As above but returns the related value, not the pointer
 **/
void * hash_get_value( const char * key, struct node ** hashtable )
{
	struct node	* p = hash_get( key, hashtable );

	if ( p )
		return p->value;
	else 
		return NULL;
}

/**
 **	Iterator
 **/
struct node * hash_get_next( struct node ** hashtable, struct node * n )
{
	unsigned long i = 0;

	if ( n )
	{
      if ( n->next )
         return n->next;

		i = get_hash( n->key ) + 1;

		if ( i == HT_SIZE )
			return NULL;
	}

	while ( (i < HT_SIZE) && !(n = hashtable[i]) )
		i++;

	return n;
}
 
/**
 **	Uses the above routine to print the hashtable
 **	It takes a pointer to a function as argument to print values
 **/
void	hash_print_next( struct node ** hashtable, char * (*vprint)(void *)  )
{
	struct node * p = *hashtable;

	while ( (p = hash_get_next( hashtable, p )) )
	{
		fprintf( stdout, "Hashtable[%ld]: key=%s value=%s\n",
					get_hash( p->key ),
					p->key, (*vprint)( p->value ));
	}
}

/**
 **	Prints the hashtable contents
 **/
void	hash_print( struct node ** hashtable, char * (*vprint)(void *)	)
{
	unsigned long	i;
	struct node	*	p;

	for( i = 0; i < HT_SIZE; i++ )
	{
		for ( p = hashtable[ i ] ; p ; p = p->next )
		{
			fprintf( stdout, "Hashtable[%ld]: key=%s value=%s\n",
						i, p->key, (*vprint)( p->value ));
		}
	}
}

/**
 **	Dragon Book hash algo ( h * 31 )
 **/
unsigned long get_hash( const char * s )
{
	const char	* ss = s;
	unsigned long h = 0, g;

	for (; *ss != 0; ss++)
	{
		h = (h << 4) + *ss;
		if ( (g = h & 0xf0000000) )
		{
			h ^= g >> 24;
			h ^= g;
		}
	}
	return ( h % HT_SIZE );
}
