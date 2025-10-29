/*
 * Roberto Puzzanghera - https://www.sagredo.eu
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

/*
 * Recipient check for s/qmail.
 * Just call this program within /var/qmail/control/recipients as follows:
 * echo "*|~vpopmail/bin/vrcptcheck" > /var/qmail/control/recipients

 * @file vrcptcheck.c
   @return 0: virtual user exists
           1: virtual user does not exist
           111: temporary problem
 */

#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "vutil.h"

#define FDAUTH 3
char inputbuf[MAX_BUFF];

void pam_exit(int fail)
{
  int i;
  close(FDAUTH);
  for (i = 0; i < sizeof(inputbuf); ++i) inputbuf[i] = 0;
  vexit(fail);
}

void main()
{
  char path[MAX_BUFF];

  /* read input */
  if (read(FDAUTH, inputbuf, sizeof(inputbuf)) == -1)
  {
    fprintf(stderr, "qmail-smtpd: Error while reading file descriptor in vrcptcheck\n");
    pam_exit(111);
  }
  close(FDAUTH);

  /* retrieve username/domain (assuming that MAV has already been done) */
  int i = 0;
  char *p = strtok (inputbuf, "@");
  char *recipient[2];
  while (p != NULL)
  {
    recipient[i++] = p;
    p = strtok (NULL, "@");
  }

  /************ recipient check ****************/

  /* get the domain path */
  snprintf(path, MAX_BUFF, "%s", vget_assign(recipient[1], NULL, 0, NULL, NULL));

  if ( isExistingAnyAddress(recipient[1], recipient[0], path) ) pam_exit(0);
  else pam_exit(1);
}
