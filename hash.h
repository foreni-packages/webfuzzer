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

#include <stdio.h>
#include <string.h>

struct node {
   char  *  key;
   void  *  value;
   struct node * next;
};

unsigned long get_hash( const char * s );

struct node * hash_get( const char * key, struct node ** ht );

void * hash_get_value( const char * key, struct node ** ht );

int hash_insert( const char * key, void * value, struct node ** ht );

struct node * hash_get_next( struct node ** hashtable, struct node * n );

void hash_print_next( struct node ** hashtable, char * (*vprint)(void *) );

void hash_print( struct node ** hashtable, char * (*vprint)(void *) );

#define  HT_SIZE        	101
