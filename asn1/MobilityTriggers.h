/*
 * Generated by asn1c-0.9.23 (http://lionet.info/asn1c)
 * From ASN.1 module "MAP-MS-DataTypes"
 * 	found in "../asn1src/MAP-MS-DataTypes.asn"
 * 	`asn1c -gen-PER -fskeletons-copy -fnative-types`
 */

#ifndef	_MobilityTriggers_H_
#define	_MobilityTriggers_H_


#include <asn_application.h>

/* Including external dependencies */
#include "MM-Code.h"
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* MobilityTriggers */
typedef struct MobilityTriggers {
	A_SEQUENCE_OF(MM_Code_t) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} MobilityTriggers_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_MobilityTriggers;

#ifdef __cplusplus
}
#endif

#endif	/* _MobilityTriggers_H_ */
#include <asn_internal.h>
