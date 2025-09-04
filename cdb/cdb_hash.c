#include "cdb.h"

uint32 cdb_hash(char *buf, int len)
{
  uint32 h;

  h = 5381;
  while (len) {
    --len;
    h += (h << 5);
    h ^= (uint32) *buf++;
  }
  return h;
}
