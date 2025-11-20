/*
 * Copyright (C) 1999-2009 Inter7 Internet Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 *
 */

#include "vpopmail.h"

//////////////////////////////////////////////////////////////////////
//
//   map of function groups within this file
//
//   utility functions
//      str_replace, file_exists
//
//   isSomething functions
//      isValidMailingList, isExistingAlias, isExistingUser, isExistingAddress
//

//////////////////////////////////////////////////////////////////////
//
//   utility functions
//

/*
 *  replace all instances of orig with repl in s.
 */
void str_replace (char *s, char orig, char repl);


/*
 * return 1 if filename is an existing file
 */
int file_exists (char *filename);

//////////////////////////////////////////////////////////////////////
//
//   isSomething functions
//

/*
 *  See if the specified address is a mailing list
 *  (both dot-qmail and SQL)
 */
int isValidMailList ( char *path, char *Name );


/*
 *  See if the specified address is an alias (dot-qmail) or
 *  a SQL valias. This is called 'forward' in qmailadmin.
 */
int isExistingAlias ( char *path, char *Name, char *Domain );


/*
 *  See if the specified address is an autoresponder (robot).
 *  This function is used by qmailadmin.
 */
int isExistingRobot ( char *path, char *Name );


/*
 *  See if the specified address is a POP user
 */
int isExistingUser( char *Name, char *Domain );


/*
 *  See if the specified address is a valid address of any kind.
 */
int isExistingAddress( char *Domain, char *Name, char *Path );


/*
 *  check dot-qmail alias file
 *  See if the specified alias name exists in qmail/alias
 */
int isQmailAlias (char *Name);


/*
 *  is Existing Any Address
 *
 *  See if the specified address is a valid address of any kind
 *  valiases and qmail/alias/.qmail-something included.
 */
int isExistingAnyAddress( char *Domain, char *Name, char *Path );
