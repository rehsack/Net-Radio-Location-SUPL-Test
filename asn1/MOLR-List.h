/*
 * Generated by asn1c-0.9.23 (http://lionet.info/asn1c)
 * From ASN.1 module "MAP-MS-DataTypes"
 * 	found in "../asn1src/MAP-MS-DataTypes.asn"
 * 	`asn1c -gen-PER -fskeletons-copy -fnative-types`
 */

#ifndef	_MOLR_List_H_
#define	_MOLR_List_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct MOLR_Class;

/* MOLR-List */
typedef struct MOLR_List {
	A_SEQUENCE_OF(struct MOLR_Class) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} MOLR_List_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_MOLR_List;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "MOLR-Class.h"

#endif	/* _MOLR_List_H_ */
#include <asn_internal.h>
