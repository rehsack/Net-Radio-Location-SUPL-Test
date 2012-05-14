/*
 * Generated by asn1c-0.9.23 (http://lionet.info/asn1c)
 * From ASN.1 module "MAP-MS-DataTypes"
 * 	found in "../asn1src/MAP-MS-DataTypes.asn"
 * 	`asn1c -gen-PER -fskeletons-copy -fnative-types`
 */

#ifndef	_SpecificAPNInfo_H_
#define	_SpecificAPNInfo_H_


#include <asn_application.h>

/* Including external dependencies */
#include "APN.h"
#include "PDN-GW-Identity.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct ExtensionContainer;

/* SpecificAPNInfo */
typedef struct SpecificAPNInfo {
	APN_t	 apn;
	PDN_GW_Identity_t	 pdn_gw_Identity;
	struct ExtensionContainer	*extensionContainer	/* OPTIONAL */;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SpecificAPNInfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SpecificAPNInfo;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "ExtensionContainer.h"

#endif	/* _SpecificAPNInfo_H_ */
#include <asn_internal.h>
