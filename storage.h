/*
   * Copyright (C) 2009 Inter7 Internet Technologies, Inc.
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

#ifndef __STORAGE_H_
#define __STORAGE_H_

#include "config.h"
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <inttypes.h>

/*
 * 64-bit endian conversion helpers
 *
 * Goal:
 *  - OpenBSD: use sys/endian.h (htobe64 / be64toh)
 *  - BSD/Linux: use bswap64 if available
 *  - Never use __bswap_64 (glibc internal, non-portable)
 */

#if defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__NetBSD__)
  #include <sys/endian.h>
  #define ntohll(x) be64toh(x)
  #define htonll(x) htobe64(x)

#elif defined(__APPLE__)
  #include <libkern/OSByteOrder.h>
  #define ntohll(x) OSSwapBigToHostInt64(x)
  #define htonll(x) OSSwapHostToBigInt64(x)

#elif defined(HAVE_ENDIAN_H)
  #include <endian.h>
  #define ntohll(x) be64toh(x)
  #define htonll(x) htobe64(x)

#elif defined(HAVE_BYTESWAP_H)
  #include <byteswap.h>
  #define ntohll(x) bswap_64(x)
  #define htonll(x) bswap_64(x)

#else
  #error "No portable 64-bit endian conversion available"
#endif

/*
 * Safety fallback for missing limits
 */
#ifndef LLONG_MAX
#define LLONG_MAX 9223372036854775807LL
#endif

/*
 * Arbitrary storage counts
 */
typedef uint64_t storage_t;

#endif /* __STORAGE_H_ */
