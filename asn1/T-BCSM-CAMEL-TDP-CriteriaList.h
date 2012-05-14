/*
 * Generated by asn1c-0.9.23 (http://lionet.info/asn1c)
 * From ASN.1 module "MAP-MS-DataTypes"
 * 	found in "../asn1src/MAP-MS-DataTypes.asn"
 * 	`asn1c -gen-PER -fskeletons-copy -fnative-types`
 */

#ifndef	_T_BCSM_CAMEL_TDP_CriteriaList_H_
#define	_T_BCSM_CAMEL_TDP_CriteriaList_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct T_BCSM_CAMEL_TDP_Criteria;

/* T-BCSM-CAMEL-TDP-CriteriaList */
typedef struct T_BCSM_CAMEL_TDP_CriteriaList {
	A_SEQUENCE_OF(struct T_BCSM_CAMEL_TDP_Criteria) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} T_BCSM_CAMEL_TDP_CriteriaList_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_T_BCSM_CAMEL_TDP_CriteriaList;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "T-BCSM-CAMEL-TDP-Criteria.h"

#endif	/* _T_BCSM_CAMEL_TDP_CriteriaList_H_ */
#include <asn_internal.h>
