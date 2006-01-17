#ifndef VALIAS 
/*
 * $Id: vpalias.c,v 1.6.2.2 2006-01-17 18:50:22 tomcollins Exp $
 * Copyright (C) 2000-2004 Inter7 Internet Technologies, Inc.
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
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include "config.h"
#include "vpopmail.h"
#include "vauth.h"

/* Globals */
static char alias_line[MAX_ALIAS_LINE];
static char Dir[156];
static int max_names, num_names, cur_name;
static char **names = NULL;

#define MAX_FILE_SIZE 156
static FILE *alias_fs = NULL;
static char mydomain[MAX_FILE_SIZE];

/* forward declarations */
char *valias_next_return_line(char *alias);
char *valias_select_names_next();
void valias_select_names_end();

char *valias_select( char *alias, char *domain )
{
 char *tmpstr;
 struct stat mystat;
 static char tmpbuf[156];
 uid_t uid;
 gid_t gid;
 int i;
 char *p;

    if ( alias == NULL )  { 
      verrori=VA_NULL_POINTER;  
      return( NULL );
    }

    if ( domain == NULL ) { 
      verrori=VA_NULL_POINTER;
      return( NULL );
    }

    if ( strlen(alias) > MAX_PW_NAME ) {
      verrori = VA_USER_NAME_TOO_LONG;
      return( NULL );
    }

    if ( strlen(domain) > MAX_PW_DOMAIN ) {
      verrori = VA_DOMAIN_NAME_TOO_LONG;
      return( NULL );
    }

    if ( alias_fs != NULL ) fclose(alias_fs);

    if ((tmpstr=vget_assign(domain,alias_line,MAX_ALIAS_LINE,&uid,&gid))==NULL) {
	printf("invalid domain, not in qmail assign file\n");
	return(NULL);
    }
    /* need to convert '.' to ':' */
    i = snprintf(tmpbuf, sizeof(tmpbuf), "%s/.qmail-", tmpstr);
    for (p = alias; (i < (int)sizeof(tmpbuf) - 1) && (*p != '\0'); p++)
      tmpbuf[i++] = (*p == '.' ? ':' : *p);
    tmpbuf[i] = '\0';
    if ( (alias_fs = fopen(tmpbuf, "r")) == NULL ) {
    	return(NULL);
    }
    return(valias_select_next());
}

char *valias_select_next()
{
 char *tmpstr;

    if ( alias_fs == NULL ) return(NULL);
    memset(alias_line,0,sizeof(alias_line));

    if ( fgets(alias_line, sizeof(alias_line), alias_fs) == NULL ) {
	fclose(alias_fs);
	alias_fs = NULL;
	return(NULL);
    }
    for(tmpstr=alias_line;*tmpstr!=0;++tmpstr) {
	if ( *tmpstr == '\n') *tmpstr = 0;
    }
    return(alias_line);
}

int valias_insert( char *alias, char *domain, char *alias_line)
{
 int i;
 char *tmpstr;
 char Dir[156];
 uid_t uid;
 gid_t gid;
 FILE *fs;

    if ( alias == NULL ) return(VA_NULL_POINTER);
    if ( domain == NULL ) return(VA_NULL_POINTER);
    if ( alias_line == NULL ) return(VA_NULL_POINTER);
    if ( strlen(alias) > MAX_PW_NAME ) return(VA_USER_NAME_TOO_LONG);
    if ( strlen(domain) > MAX_PW_DOMAIN ) return(VA_DOMAIN_NAME_TOO_LONG);
    if ( strlen(alias_line) >= MAX_ALIAS_LINE ) return(VA_ALIAS_LINE_TOO_LONG);

    if ((tmpstr = vget_assign(domain, Dir, sizeof(Dir), &uid, &gid )) == NULL) {
	printf("invalid domain, not in qmail assign file\n");
	return(-1);
    }
    strncat(Dir, "/.qmail-", sizeof(Dir)-strlen(Dir)-1);
    for(i=0;alias[i]!=0;++i) if ( alias[i] == '.' ) alias[i] = ':';
    strncat(Dir, alias, sizeof(Dir)-strlen(Dir)-1);
	
    if ( (fs = fopen(Dir, "a")) == NULL ) {
	return(-1);
    }
    chmod(Dir,0600);
    chown(Dir,uid,gid);

    fprintf(fs, "%s\n", alias_line);
    fclose(fs);
    return(0);
}

int valias_remove( char *alias, char *domain, char *alias_line)
{
  fprintf (stderr, "Error: valias_remove() not implemented for non-SQL backends.\n");
  return -1;
}

int valias_delete( char *alias, char *domain)
{
 char *tmpstr;
 char Dir[156];
 uid_t uid;
 gid_t gid;
 int i;

    if ( alias == NULL ) return(VA_NULL_POINTER); 
    if ( domain == NULL ) return(VA_NULL_POINTER);
    if ( strlen(alias) > MAX_PW_NAME ) return(VA_USER_NAME_TOO_LONG);
    if ( strlen(domain) > MAX_PW_DOMAIN ) return(VA_DOMAIN_NAME_TOO_LONG);

    if ((tmpstr = vget_assign(domain, Dir, 156, &uid, &gid )) == NULL) {
	printf("invalid domain, not in qmail assign file\n");
	return(-1);
    }
    strncat(Dir, "/.qmail-", sizeof(Dir)-strlen(Dir)-1);
    for(i=0;alias[i]!=0;++i) if ( alias[i] == '.' ) alias[i] = ':';
    strncat(Dir, alias, sizeof(Dir)-strlen(Dir)-1);
    return(unlink(Dir));
}

static int sort_compare( const void *p1, const void *p2 ) 
{
  return strcasecmp(*(char **)p1, *(char **)p2 );
}

char *valias_select_names( char *domain )
{
 static DIR *mydir = NULL;
 static struct dirent *mydirent;
 uid_t uid;
 gid_t gid;
 int countit;
 struct stat mystat;
 char filename[500];
 int i, j, len;

    if ( domain == NULL ) { 
      verrori=VA_NULL_POINTER;
      return( NULL );
    }
  
    if ( strlen(domain) > MAX_PW_DOMAIN ) {
      verrori = VA_DOMAIN_NAME_TOO_LONG;
      return( NULL );
    }

    if ( alias_fs != NULL ) {
	fclose(alias_fs); 
        alias_fs = NULL;
    }

    if ((vget_assign(domain, Dir, sizeof(Dir), &uid, &gid )) == NULL) {
	printf("invalid domain, not in qmail assign file\n");
	return(NULL);
    }

    if( names != NULL ) {
       valias_select_names_end();
    }

    /*  We are about to create an array of string pointers big
     *  enough to hold all the .qmail files in the domain directory.
     *  Not all may be used because I am ignoring the fact that mail
     *  lists have many files, but only get listed once.
     *  Its only a few bytes...
     */

    if (mydir!=NULL) closedir(mydir);
    if ( (mydir = opendir(Dir)) == NULL ) return(NULL);

    while ((mydirent=readdir(mydir))!=NULL) {
      if ( strncmp(mydirent->d_name,".qmail-", 7) == 0 &&
           strcmp(mydirent->d_name, ".qmail-default") != 0 ) {
        max_names++;
      }
    }

    /*  Now we know about how many aliases there may be.
     *  Allocate a buffer for them
     */    

    names = malloc( max_names * sizeof(char *));
    memset(names, 0, max_names * sizeof(char *));

    if (mydir!=NULL) closedir(mydir);
    if ( (mydir = opendir(Dir)) == NULL ) return(NULL);

    while ((mydirent=readdir(mydir))!=NULL) {
      if ( strncmp(mydirent->d_name,".qmail-", 7) == 0 &&
           strcmp(mydirent->d_name, ".qmail-default") != 0 ) {

        countit=0;
        sprintf(filename, "%s/%s", Dir, mydirent->d_name);
        
        if(!lstat(filename, &mystat) && S_ISLNK(mystat.st_mode)) {
          /*  It is a mailing list  */
           if( strstr(mydirent->d_name, "-default") == NULL &&
               strstr(mydirent->d_name, "-owner" ) == NULL ) {
             /*  Only count the base name, ignore the others  */
             countit=1;
          }

        }  else  {
          /*  It is a regular .qmail file  */
          countit=1;
        }

        if(countit) {
          sprintf(filename, "%s", mydirent->d_name );
          len = strlen( filename ) - 7;
          names[ num_names ] = malloc( len );
          for(i=7,j=0; j<=len; i++,j++) {
            names[num_names][j] = filename[i];
            if( ':' == filename[i] ) {
              names[num_names][j] = '.';
            }
          }
          num_names++;          
        }
      }
    }

    if (mydir!=NULL) closedir(mydir);
    qsort(names, num_names, sizeof(char *), sort_compare );    

    return(valias_select_names_next());
}

char *valias_select_names_next()
{
  if( NULL == names ) {
     return(NULL);
  
  } else if( cur_name >= num_names ) {
    return(NULL);

  }  else  {
    return(names[ cur_name++ ]);
  }
}


void valias_select_names_end()
{
 int i;

  if( NULL != names ) {
    for(i=0;i<num_names;i++){
      free(names[i]);
    }
    free(names);
    names=NULL;
  }
  max_names=0;
  num_names=0;
  cur_name=0;
} 


char *valias_select_all( char *alias, char *domain )
{
 uid_t uid;
 gid_t gid;

    if ( alias == NULL )  { 
      verrori=VA_NULL_POINTER;  
      return( NULL );
    }

    if ( domain == NULL ) { 
      verrori=VA_NULL_POINTER;
      return( NULL );
    }
  
    if ( strlen(domain) >= MAX_PW_DOMAIN ) {
      verrori = VA_DOMAIN_NAME_TOO_LONG;
      return( NULL );
    }

    if ( alias_fs != NULL ) {
	fclose(alias_fs); 
        alias_fs = NULL;
    }

    if ((vget_assign(domain, Dir, sizeof(Dir), &uid, &gid )) == NULL) {
	printf("invalid domain, not in qmail assign file\n");
	return(NULL);
    }

    strcpy(alias, valias_select_names( domain ));
    strncpy(mydomain, domain, MAX_FILE_SIZE);
    return(valias_select(alias, domain));
}

char *valias_select_all_next(char *alias)
{
 char *tmpstr;

  if ( alias == NULL )  { 
    verrori=VA_NULL_POINTER;  
    return( NULL );
  }
  
  tmpstr=valias_select_next(alias);

  if (NULL == tmpstr) {
    tmpstr=valias_select_names_next();

    if( NULL == tmpstr ) {
      return( NULL );

    } else {
      strcpy(alias, tmpstr);
      return( valias_select(alias, mydomain));
    }
  }  else  {
    return( tmpstr );
  }
}
#endif
