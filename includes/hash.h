#ifndef HASH_H
# define HASH_H

/* Hash functions are located in the hash/ directory */

/* sha384.c */
char		*sha384(char *str, size_t size);

/* sha512.c */
char		*sha512(char *str, size_t size);

/* sha224.c */
char		*sha224(char *str, size_t size);

/* sha256.c */
char		*sha256(char *str, size_t size);

/* md5.c */
char		*md5(char *str, size_t size);

#endif
