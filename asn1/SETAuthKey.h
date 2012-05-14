/*
 * Generated by asn1c-0.9.23 (http://lionet.info/asn1c)
 * From ASN.1 module "SUPL-RESPONSE"
 * 	found in "../asn1src/SUPL-RESPONSE.asn"
 * 	`asn1c -gen-PER -fskeletons-copy -fnative-types`
 */

#ifndef	_SETAuthKey_H_
#define	_SETAuthKey_H_


#include <asn_application.h>

/* Including external dependencies */
#include <BIT_STRING.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum SETAuthKey_PR {
	SETAuthKey_PR_NOTHING,	/* No components present */
	SETAuthKey_PR_shortKey,
	SETAuthKey_PR_longKey,
	/* Extensions may appear below */
	
} SETAuthKey_PR;

/* SETAuthKey */
typedef struct SETAuthKey {
	SETAuthKey_PR present;
	union SETAuthKey_u {
		BIT_STRING_t	 shortKey;
		BIT_STRING_t	 longKey;
		/*
		 * This type is extensible,
		 * possible extensions are below.
		 */
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SETAuthKey_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SETAuthKey;

#ifdef __cplusplus
}
#endif

#endif	/* _SETAuthKey_H_ */
#include <asn_internal.h>
