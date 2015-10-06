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

#include "webfuzzer.h"

/** ugly hack for cross site script **/

#define  XSS         -2
#define  DEFAULT_VAL "1"

/**
 **	Must be a command that puts PATTERN to stdout
 **/
#define	COMMAND		"/bin/echo"

#define	XSS_MSG		"Possible Cross Site Scripting"
#define MICROSOFT       "Possible SQL injection in MS SQL"
#define MYSQL           "Possible SQL injection in MySql"
#define PGSQL           "Possible SQL injection in PostgreSQL"
#define PHP             "Possible PHP inclusion warning"
#define ASP             "ASP generic error"
#define VB              "Visual basic generic error"
#define DIRTRAV         "Possible directory traversal"
#define CODEEXE         "Possible code execution"
#define GENERIC         "Generic server error"

/**
 **     Every line added here makes webfuzzer run MUCH slower
 **/

#define TFILE           "/etc/services"
#define TSTRING		"tcpmux"
#define TPATTERN	"w00t"

#define	TWINFILE	"c:\winnt\desktop.ini"

struct error ERRORS[]=
{

{ "Microsoft OLE DB Provider for"                       , MICROSOFT     },
{ "ODBC Microsoft Access Driver"                        , MICROSOFT     },
{ "ODBC SQL Server Driver"                              , MICROSOFT     },
{ "Microsoft VBScript runtime"                          , VB            },
{ "Response object"                                     , ASP           },
{ "Access denied for user"                              , MYSQL         },
{ "You have an error in your SQL syntax"                , MYSQL         },
{ "Incorrect column"                                    , MYSQL         },
{ "Can't find record"                                   , MYSQL         },
{ "Unknown table"                                       , MYSQL         },
{ "Unknown column"                                      , MYSQL         },
{ "Column count doesn't match"                          , MYSQL         },
{ "not a valid MySQL result"                            , MYSQL         },
{ "MySQL Connection Failed"                             , MYSQL         },
{ "PostgreSQL query failed"                             , PGSQL         },
{ "for inclusion (include_path="                        , PHP           },
{ "Undefined class name"                                , PHP           },
{ "Call to undefined function:"                         , PHP           },
{ "No such file or directory"                           , PHP           },
{ "<b>Warning</b>:"                                     , GENERIC       },

{ TPATTERN	, CODEEXE	},
{ TSTRING	, DIRTRAV	},
/*
 * TODO
 *	{ TWINFILE	, DIRTRAV	}, 
 *
*/
{ NULL, NULL }

};

struct technic TECHNICS[]=
{

/**
 **	SQL injection, ASP/VB errors and PHP includes
 **/

{ "yop"		,	TFSAP	},
{ "6,6"		,	TFSAP   },
{ "'OR"		,	TFSAP   },
{ "OR'"  	,	TFSAP   },
{ "yop'"	,	TFSAP   },
{ "'yop"	,	TFSAP   },

/**
 **	Meta characters/shell escapes
 **/

{ "x\n" COMMAND "+" TPATTERN		,	TFSHELL	},
{ "`" COMMAND "+" TPATTERN "`"		,	TFSHELL	},	
{ "&&+" COMMAND "+" TPATTERN		,	TFSHELL	},
{ "x;" COMMAND "+" TPATTERN		,	TFSHELL	},
{ "x\\|" COMMAND "+" TPATTERN		,	TFSHELL	},
{ "x$(" COMMAND "+" TPATTERN ")"	,	TFSHELL	},
{ "x|" COMMAND "+" TPATTERN		,	TFSHELL	},
{ "<" TFILE				,	TFSHELL	},

/**	Insecure perl open	**/

{ COMMAND "+" TPATTERN "|%00"		,	TFPERL	},
{ "x|" COMMAND "+" TPATTERN "%00"	,	TFPERL	},
{ COMMAND "+" TPATTERN "|"		,	TFPERL	},

/**	Directory traversal	**/

{ "../../../../../../../../../../.." TFILE     		,	TFDIR	},
{ ".\\./.\\./.\\./.\\./.\\./.\\./.\\./.\\./.\\." TFILE	,	TFDIR	},
{ ".../...//.../...//.../...//.../...//.../...//.../...//"	
 ".../...//.../...//.../...//.../.../" TFILE  		,	TFDIR	},

/*** uncomment at will

{ ".\"./\".\"./\".\"./\".\"./\".\"./\".\"./\".\"./\".\"./\".\"./\".\"./\".\""
  "./\".\"./\"" TFILE" },

***/

 /**	Poisoned NULL **/

{ "../../../../../../../../../../.." TFILE "%00"	     	,     TFDIR },
{ ".\\./.\\./.\\./.\\./.\\./.\\./.\\./.\\./.\\." TFILE "%00"	,     TFDIR },
{ ".../...//.../...//.../...//.../...//.../...//.../...//"
 ".../...//.../...//.../...//.../.../" TFILE "%00"		,     TFDIR },
 
 { NULL, 0 }

};
