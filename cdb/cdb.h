#ifndef CDB_H
#define CDB_H

#include "uint32.h"

extern uint32 cdb_hash(char *, int);
extern uint32 cdb_unpack(unsigned char *);

extern int cdb_bread(int, char *, int);
extern int cdb_seek(int, char *, unsigned int, uint32 *);

#endif
