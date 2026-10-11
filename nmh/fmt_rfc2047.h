/* fmt_rfc2047.h -- decode RFC-2047 header format 
 *
 * This code is Copyright (c) 2017, by the authors of nmh.  See the
 * COPYRIGHT file in the root directory of the nmh distribution for
 * complete copyright information. */

/*
 * Decode two characters into their quoted-printable representation.
 *
 * Arguments are:
 *
 * byte1	- First character of Q-P representation
 * byte2	- Second character of Q-P representation
 *
 * Returns the decoded value, -1 if the conversion failed.
 */
int decode_qp(unsigned char byte1, unsigned char byte2) CONST;

/*
 * Decode first argument string to destination of specified length.
 * Returns length in octets of decoded string, excluding terminating
 * NUL, or -1 if unable to decode.  The last argument can optionally
 * specify the destination charset.  If NULL, the user's locale charset
 * is used.
 */
ssize_t decode_rfc2047(char *, char *, size_t, const char *);
