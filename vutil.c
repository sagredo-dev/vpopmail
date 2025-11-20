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
#include <fcntl.h>
#include <signal.h>
#include <ctype.h>

#include "config.h"
#include "vpopmail.h"
#include "vauth.h"

char dotqmailfn[MAX_BUFF], Buffer[MAX_BUFF];

//////////////////////////////////////////////////////////////////////
//
//   utility functions
//

/*
 *  replace all instances of orig with repl in s.
 */
void str_replace (char *s, char orig, char repl) {
    while (*s) {
        if (*s == orig) *s = repl;
        s++;
    }
}


/*
 * return 1 if filename is an existing file
 *
 * Would this be better using stat?
 *
 */
int file_exists (char *filename) {
   FILE *f = fopen(filename, "r");
   if (f) { fclose(f); return 1; }
   else return 0;
}

//////////////////////////////////////////////////////////////////////
//
//   isSomething functions
//

/*
 *  See if the specified address is a mailing list
 *  (both dot-qmail and SQL)
 */
int isValidMailList ( char *path, char *Name )
{
    FILE *fs = NULL;
    char FileName[MAX_BUFF];

    /* Replace . with : in dot-qmail file */
    snprintf (dotqmailfn, sizeof(dotqmailfn), ".qmail-%s", Name);
    str_replace (dotqmailfn+7, '.', ':');

    snprintf( FileName, MAX_BUFF, "%s/%s", path, dotqmailfn );
    if ( (fs=fopen(FileName,"r"))==NULL) return 0;
    fgets( Buffer, sizeof(Buffer), fs);
    fclose(fs);
    /* See if "ezmlm-reject" or "ezmlm-send" is present in the dot-qmail file */
    return ( strstr( Buffer, "ezmlm-reject") != 0 ||
        strstr( Buffer, "ezmlm-send")   != 0 );
}


/*
 *  See if the specified address is an alias (dot-qmail) or
 *  a SQL valias. This is called 'forward' in qmailadmin.
 */
int isExistingAlias ( char *path, char *Name, char *Domain )
{
    FILE *fs = NULL;
    char FileName[MAX_BUFF];
    int result = 0;
    char *aliasline, *space, *ar, *ez;

    /* Replace . with : in dot-qmail file */
    snprintf (dotqmailfn, sizeof(dotqmailfn), ".qmail-%s", Name);
    str_replace (dotqmailfn+7, '.', ':');

    /* ignore .qmail-default/.qmail-default-something */
    if (strncmp(dotqmailfn, ".qmail-default", 14) == 0) return 0;

    /* See if dot-qmail file exists */
    snprintf( FileName, MAX_BUFF, "%s/%s", path, dotqmailfn );
    if ( (fs=fopen(FileName,"r")) != NULL) {
      fgets(Buffer, sizeof(Buffer), fs);
      /*
        See if "ezmlm-reject" or "ezmlm-send" or "autorespond" are
        present in the dot-qmail file. If yes, it's a m/l or a robot.
       */
      if ( strstr( Buffer, "ezmlm-reject" ) == 0 &&
           strstr( Buffer, "ezmlm-send" )   == 0 &&
           strstr( Buffer, "autorespond" )  == 0
         ) result = 1;
      fclose(fs);
    }
#ifdef VALIAS
    // catch sql valiases
    else {
      aliasline = valias_select (Name, Domain);
      /* Autoresponder/Mailing List detection algorithm:
       * We're looking for either '/autorespond ' or '/ezmlm-reject '
       * to appear in the first line, before a space appears.
       */
      if (aliasline != NULL) {
        space = strstr (aliasline, " ");
        ar = strstr (aliasline, "/autorespond ");
        ez = strstr (aliasline, "/ezmlm-reject ");
        /* is autoresponder? */
        if (ar && space && (ar < space)) result = 0;
        /* is ezmlm? */
        else if (ez && space && (ez < space)) result = 0;
        /* it's a valias */
        else result = 1;
      }
      else result = 0;
    }
#endif

    return result;
}


/*
 *  See if the specified address is an autoresponder (robot).
 *  This function is used by qmailadmin.
 */
int isExistingRobot ( char *path, char *Name )
{
    FILE *fs = NULL;
    char FileName[MAX_BUFF], upname[MAX_BUFF];
    size_t i;

    /* copy Name into upname and uppercase it */
    for (i = 0; i < sizeof(upname)-1 && Name[i]; ++i)
        upname[i] = (char) toupper((unsigned char)Name[i]);
    upname[i] = '\0';

    snprintf(FileName, MAX_BUFF, "%s/%s/message", path, upname);

    if (file_exists(FileName)) return 1;
    else return 0;
}


/*
 * See if the specified address is a POP user
 */
int isExistingUser( char *Name, char *Domain )
{
    int result = 1;
    struct vqpasswd *mypw;

    if ( (mypw = vauth_getpw( Name, Domain )) == NULL ) result = 0;

    return result;
}


/*
 *  is Existing Address
 *
 *  See if the specified address is a valid address of any kind.
 *  We are not including qmail/alias/.qmail-something addresses here.
 */
int isExistingAddress( char *Domain, char *Name, char *Path )
{
    //  Set it to false
    int result = 0;

    //  Try things that might make it true
         if( isExistingUser( Name, Domain )) result = 1;
    else if( isExistingAlias( Path, Name, Domain )) result = 1;
    else if( isExistingRobot( Path, Name )) result = 1;

    return result;
}

/*
 *  check dot-qmail alias file
 *  See if the specified alias name exists in qmail/alias
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
         if( isExistingUser(Name, Domain) ) result = 1;
    // catch .qmail-something, valiases, robots and m/l included
    else if( isExistingAlias(Path, Name, Domain) )  result = 1;
    // catch robots (autoresponder)
    else if( isExistingRobot(Path, Name) )  result = 1;
    // catch qmail/alias/.qmail-something aliases
    else if( isQmailAlias(Name) ) result = 1;

    return result;
}
