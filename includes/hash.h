#ifndef HASH_H
# define HASH_H

/* sha384.c */
char		*sha384(uint8_t *str, size_t size);

/* sha512.c */
char		*sha512(uint8_t *str, size_t size);

/* sha224.c */
char		*sha224(uint8_t *str, size_t size);

/* sha256.c */
char		*sha256(uint8_t *str, size_t size);

/* md5.c */
char		*md5(uint8_t *str, size_t size);

#endif
