/*
 * Generated by asn1c-0.9.23 (http://lionet.info/asn1c)
 * From ASN.1 module "RRLP-Components"
 * 	found in "../asn1src/RRLP-Components.asn"
 * 	`asn1c -gen-PER -fskeletons-copy -fnative-types`
 */

#ifndef	_GANSSRealTimeIntegrity_H_
#define	_GANSSRealTimeIntegrity_H_


#include <asn_application.h>

/* Including external dependencies */
#include "SeqOfBadSignalElement.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* GANSSRealTimeIntegrity */
typedef struct GANSSRealTimeIntegrity {
	SeqOfBadSignalElement_t	 ganssBadSignalList;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} GANSSRealTimeIntegrity_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_GANSSRealTimeIntegrity;

#ifdef __cplusplus
}
#endif

#endif	/* _GANSSRealTimeIntegrity_H_ */
#include <asn_internal.h>
