#ifndef HASH_H
# define HASH_H

/* sha384.c */
uint8_t		*sha384(uint8_t *str, size_t size, size_t *res_len);

/* sha512.c */
uint8_t		*sha512(uint8_t *str, size_t size, size_t *res_len);

/* sha224.c */
uint8_t		*sha224(uint8_t *str, size_t size, size_t *res_len);

/* sha256.c */
uint8_t		*sha256(uint8_t *str, size_t size, size_t *res_len);

/* md5.c */
uint8_t		*md5(uint8_t *str, size_t size, size_t *res_len);

#endif
