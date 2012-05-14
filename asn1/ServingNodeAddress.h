/*
 * Generated by asn1c-0.9.23 (http://lionet.info/asn1c)
 * From ASN.1 module "MAP-LCS-DataTypes"
 * 	found in "../asn1src/MAP-LCS-DataTypes.asn"
 * 	`asn1c -gen-PER -fskeletons-copy -fnative-types`
 */

#ifndef	_ServingNodeAddress_H_
#define	_ServingNodeAddress_H_


#include <asn_application.h>

/* Including external dependencies */
#include "ISDN-AddressString.h"
#include "DiameterIdentity.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum ServingNodeAddress_PR {
	ServingNodeAddress_PR_NOTHING,	/* No components present */
	ServingNodeAddress_PR_msc_Number,
	ServingNodeAddress_PR_sgsn_Number,
	ServingNodeAddress_PR_mme_Number
} ServingNodeAddress_PR;

/* ServingNodeAddress */
typedef struct ServingNodeAddress {
	ServingNodeAddress_PR present;
	union ServingNodeAddress_u {
		ISDN_AddressString_t	 msc_Number;
		ISDN_AddressString_t	 sgsn_Number;
		DiameterIdentity_t	 mme_Number;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ServingNodeAddress_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_ServingNodeAddress;

#ifdef __cplusplus
}
#endif

#endif	/* _ServingNodeAddress_H_ */
#include <asn_internal.h>
