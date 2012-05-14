/*
 * Generated by asn1c-0.9.23 (http://lionet.info/asn1c)
 * From ASN.1 module "MAP-MS-DataTypes"
 * 	found in "../asn1src/MAP-MS-DataTypes.asn"
 * 	`asn1c -gen-PER -fskeletons-copy -fnative-types`
 */

#ifndef	_LSAInformationWithdraw_H_
#define	_LSAInformationWithdraw_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NULL.h>
#include "LSAIdentityList.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum LSAInformationWithdraw_PR {
	LSAInformationWithdraw_PR_NOTHING,	/* No components present */
	LSAInformationWithdraw_PR_allLSAData,
	LSAInformationWithdraw_PR_lsaIdentityList
} LSAInformationWithdraw_PR;

/* LSAInformationWithdraw */
typedef struct LSAInformationWithdraw {
	LSAInformationWithdraw_PR present;
	union LSAInformationWithdraw_u {
		NULL_t	 allLSAData;
		LSAIdentityList_t	 lsaIdentityList;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LSAInformationWithdraw_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_LSAInformationWithdraw;

#ifdef __cplusplus
}
#endif

#endif	/* _LSAInformationWithdraw_H_ */
#include <asn_internal.h>
