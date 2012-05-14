/*-
 * Copyright (c) 2003 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#ifndef	_OCTET_STRING_H_
#define	_OCTET_STRING_H_

#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct OCTET_STRING {
	uint8_t *buf;	/* Buffer with consecutive OCTET_STRING bits */
	int size;	/* Size of the buffer */

	asn_struct_ctx_t _asn_ctx;	/* Parsing across buffer boundaries */
} OCTET_STRING_t;

extern asn_TYPE_descriptor_t asn_DEF_OCTET_STRING;

asn_struct_free_f OCTET_STRING_free;
asn_struct_print_f OCTET_STRING_print;
asn_struct_print_f OCTET_STRING_print_utf8;
ber_type_decoder_f OCTET_STRING_decode_ber;
der_type_encoder_f OCTET_STRING_encode_der;
xer_type_decoder_f OCTET_STRING_decode_xer_hex;		/* Hexadecimal */
xer_type_decoder_f OCTET_STRING_decode_xer_binary;	/* 01010111010 */
xer_type_decoder_f OCTET_STRING_decode_xer_utf8;	/* ASCII/UTF-8 */
xer_type_encoder_f OCTET_STRING_encode_xer;
xer_type_encoder_f OCTET_STRING_encode_xer_utf8;
per_type_decoder_f OCTET_STRING_decode_uper;
per_type_encoder_f OCTET_STRING_encode_uper;

/******************************
 * Handy conversion routines. *
 ******************************/

/*
 * This function clears the previous value of the OCTET STRING (if any)
 * and then allocates a new memory with the specified content (str/size).
 * If size = -1, the size of the original string will be determined
 * using strlen(str).
 * If str equals to NULL, the function will silently clear the
 * current contents of the OCTET STRING.
 * Returns 0 if it was possible to perform operation, -1 otherwise.
 */
int OCTET_STRING_fromBuf(OCTET_STRING_t *s, const char *str, int size);

/* Handy conversion from the C string into the OCTET STRING. */
#define	OCTET_STRING_fromString(s, str)	OCTET_STRING_fromBuf(s, str, -1)

/*
 * Allocate and fill the new OCTET STRING and return a pointer to the newly
 * allocated object. NULL is permitted in str: the function will just allocate
 * empty OCTET STRING.
 */
OCTET_STRING_t *OCTET_STRING_new_fromBuf(asn_TYPE_descriptor_t *td,
	const char *str, int size);

/*
 * This function clears the previous value of the OCTET STRING (if any)
 * and then allocates a new memory with the specified content (str/size)
 * and copies the source alternating into the upper and lower half-bytes
 * of the OCTET STRING. Odd sources always create a trailing '0' lower
 * half-byte.
 * If size = -1, the size of the original string will be determined
 * using strlen(str).
 * If str equals to NULL, the function will silently clear the
 * current contents of the OCTET STRING.
 * Returns 0 if it was possible to perform operation, -1 otherwise.
 */
int BCD_OCTET_STRING_fromBuf(OCTET_STRING_t *s, const char *str, int size);

/* Handy conversion from the C string containing BCD into the OCTET STRING. */
#define	BCD_OCTET_STRING_fromString(s, str)	BCD_OCTET_STRING_fromBuf(s, str, -1)

/*
 * This function returns the size of the given octet string or
 * -1 on error.
 */
static inline ssize_t OCTET_STRING_size(OCTET_STRING_t *s) { return s ? s->size : -1; }

/*
 * This function extracts the content of an octet string into the given
 * buffer.
 * Returns the number of bytes written into buffer or a negative error
 * code from errno.h (EINVAL for invalid argument, ENOMEM when not
 * enough memory for copying)
 */
ssize_t OCTET_STRING_toBuf(OCTET_STRING_t *s, uint8_t *buf, ssize_t bufsiz);
/*
 * This function extracts the content of an octet string which contains
 * binary coded decimals into the given buffer. Each half-byte is expanded
 * and put separately.
 * Returns the number of bytes written into buffer or a negative error
 * code from errno.h (EINVAL for invalid argument, ENOMEM when not
 * enough memory for copying)
 */
ssize_t BCD_OCTET_STRING_toBuf(OCTET_STRING_t *s, uint8_t *buf, ssize_t bufsiz);
/*
 * This function extracts the content of an octet string into a newly
 * allocated buffer and puts the pointer to the newly allocated buffer
 * into *buf.
 * Returns the number of bytes written into buffer or a negative error
 * code from errno.h (EINVAL for invalid argument, ENOMEM when unable
 * to allocate memory for copying)
 */
ssize_t OCTET_STRING_toNewBuf(OCTET_STRING_t *s, uint8_t **buf);
/*
 * This function extracts the content of an octet string which contains
 * binary coded decimals into a newly allocated buffer and puts the
 * pointer to the newly allocated buffer into *buf. Each half-byte is
 * expanded and put separately.
 * Returns the number of bytes written into buffer or a negative error
 * code from errno.h (EINVAL for invalid argument, ENOMEM when unable
 * to allocate memory for copying)
 */
ssize_t BCD_OCTET_STRING_toNewBuf(OCTET_STRING_t *s, uint8_t **buf);

/*
 * This function extracts the content of an octet string into the given
 * buffer and appends the trailing '\0' byte.
 * Returns the number of bytes written into buffer or a negative error
 * code from errno.h (EINVAL for invalid argument, ENOMEM when not
 * enough memory for copying)
 */
ssize_t OCTET_STRING_toStr(OCTET_STRING_t *s, char *str, ssize_t strsiz);
/*
 * This function extracts the content of an octet string which contains
 * binary coded decimals into the given buffer and appends the trailing
 * '\0' byte. Each half-byte is expanded and put separately.
 * Returns the number of bytes written into buffer or a negative error
 * code from errno.h (EINVAL for invalid argument, ENOMEM when not
 * enough memory for copying)
 */
ssize_t BCD_OCTET_STRING_toStr(OCTET_STRING_t *s, char *str, ssize_t strsiz);
/*
 * This function extracts the content of an octet string into a newly
 * allocated buffer, appends the trailing '\0' byte and puts the pointer
 * to the newly allocated buffer into *buf.
 * Returns the number of bytes written into buffer or a negative error
 * code from errno.h (EINVAL for invalid argument, ENOMEM when unable
 * to allocate memory for copying)
 */
ssize_t OCTET_STRING_toNewStr(OCTET_STRING_t *s, char **str);
/*
 * This function extracts the content of an octet string which contains
 * binary coded decimals into a newly allocated buffer, appends the
 * trailing '\0' byte and puts the pointer to the newly allocated buffer
 * into *buf. Each half-byte is expanded and put separately.
 * Returns the number of bytes written into buffer or a negative error
 * code from errno.h (EINVAL for invalid argument, ENOMEM when unable
 * to allocate memory for copying)
 */
ssize_t BCD_OCTET_STRING_toNewStr(OCTET_STRING_t *s, char **str);

/****************************
 * Internally useful stuff. *
 ****************************/

typedef struct asn_OCTET_STRING_specifics_s {
	/*
	 * Target structure description.
	 */
	int struct_size;	/* Size of the structure */
	int ctx_offset;		/* Offset of the asn_struct_ctx_t member */

	enum asn_OS_Subvariant {
		ASN_OSUBV_ANY,	/* The open type (ANY) */
		ASN_OSUBV_BIT,	/* BIT STRING */
		ASN_OSUBV_STR,	/* String types, not {BMP,Universal}String  */
		ASN_OSUBV_U16,	/* 16-bit character (BMPString) */
		ASN_OSUBV_U32	/* 32-bit character (UniversalString) */
	} subvariant;
} asn_OCTET_STRING_specifics_t;

#ifdef __cplusplus
}
#endif

#endif	/* _OCTET_STRING_H_ */
