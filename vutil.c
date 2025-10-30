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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <dirent.h>
#include "config.h"

#include <fcntl.h>
#include <signal.h>
#include "vpopmail.h"
#include "vauth.h"


//////////////////////////////////////////////////////////////////////
//
//   utility functions
//

 /*
  *  str_replace
  *
  *  replace all instances of orig with repl in s.
  */

void str_replace (char *s, char orig, char repl) {
    while (*s) {
        if (*s == orig) *s = repl; 
        s++;
    }
}


 /*
  * file_exists
  *
  * return 1 if filename is an existing file
  *
  * Would this be better using stat?
  *
  */

int file_exists (char *filename) {
    return(access(filename, R_OK) == 0);
}

//////////////////////////////////////////////////////////////////////
//
//   isSomething functions
//

 /*
  *  is Valid MailList
  *
  *  See if the specified address is a mailing list
  */

int isValidMailList ( char *path, char *Name )
{
    FILE *fs = NULL;
    char FileName[MAX_BUFF];
    char TmpBuf2[MAX_BUFF];

    snprintf( FileName, MAX_BUFF, "%s/.qmail-%s", path, Name );
    if ( (fs=fopen(FileName,"r"))==NULL)
        return(0);
    fgets( TmpBuf2, sizeof(TmpBuf2), fs);
    fclose(fs);
    return ( strstr( TmpBuf2, "ezmlm-reject") != 0 ||
        strstr( TmpBuf2, "ezmlm-send")   != 0 );
}


 /*
  *  is Existing Alias
  *
  *  See if the specified address is an alias.
  *  It now checks sql valiases as well.
  */

int isExistingAlias ( char *path, char *Name, char *Domain )
{
    FILE *fs = NULL;
    char FileName[MAX_BUFF];
    int result = 0;

    snprintf( FileName, MAX_BUFF, "%s/.qmail-%s", path, Name );
    if ( (fs=fopen(FileName,"r")) != NULL) {
        result = 1;
        fclose(fs);
    }
#ifdef VALIAS
    // catch sql valiases
    else if (valias_select (Name, Domain) != NULL) result = 1;
#endif

//    printf( " result: %d\n", result );
    return result;
}


 /*
  *  is Existing User
  *
  *  See if the specified address is a user
  */

int isExistingUser( char *Name, char *Domain )
{
    int result = 1;
    struct vqpasswd *mypw;

    if ( (mypw = vauth_getpw( Name, Domain )) == NULL ) {
        result = 0;
    }

    return result;
}


 /*
  *  is Existing Address
  *
  *  See if the specified address is a valid address of any kind.
  */

int isExistingAddress( char *Domain, char *Name, char *Path )
{
    //  Set it to false
    int result = 0;

    //  Try things that might make it true
         if( isExistingUser( Name, Domain )) result = 1;
    else if( isExistingAlias( Path, Name, Domain ))  result = 1;

    return result;
}

 /*
  *  check dot-qmail alias file
  *
  *  See if the specified alias name exists in qmail/alias
  *
  */
int isQmailAlias (char *Name) {
  FILE *fp;
  char FileName[MAX_BUFF];
  int result = 0;

  // look for qmail/alias/.qmail-name-default
  snprintf( FileName, MAX_BUFF, "%s/alias/.qmail-%s-default", QMAILDIR, Name );
  fp = fopen(FileName, "r");
  if (fp != NULL) {
    result = 1;
    fclose(fp);
  }
  // look for qmail/alias/.qmail-name
  else {
    snprintf( FileName, MAX_BUFF, "%s/alias/.qmail-%s", QMAILDIR, Name );
    fp = fopen(FileName, "r");
    if (fp != NULL) {
      result = 1;
      fclose(fp);
    }
  }

  return result;
}


 /*
  *  is Existing Any Address
  *
  *  See if the specified address is a valid address of any kind
  *  valiases and qmail/alias/.qmail-something included.
  */

int isExistingAnyAddress( char *Domain, char *Name, char *Path )
{
    // Set it to false
    int result = 0;

    // Try things that might make it true

    // catch regular users
         if( isExistingUser( Name, Domain )) result = 1;
    // catch .qmail-something, valiases and m/l included
    else if( isExistingAlias( Path, Name, Domain ))  result = 1;
    // catch qmail/alias/.qmail-something aliases
    else if (isQmailAlias (Name)) result = 1;

    return result;
}
