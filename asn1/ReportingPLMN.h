/*
 * Generated by asn1c-0.9.23 (http://lionet.info/asn1c)
 * From ASN.1 module "MAP-LCS-DataTypes"
 * 	found in "../asn1src/MAP-LCS-DataTypes.asn"
 * 	`asn1c -gen-PER -fskeletons-copy -fnative-types`
 */

#ifndef	_ReportingPLMN_H_
#define	_ReportingPLMN_H_


#include <asn_application.h>

/* Including external dependencies */
#include "PLMN-Id.h"
#include "RAN-Technology.h"
#include <NULL.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ReportingPLMN */
typedef struct ReportingPLMN {
	PLMN_Id_t	 plmn_Id;
	RAN_Technology_t	*ran_Technology	/* OPTIONAL */;
	NULL_t	*ran_PeriodicLocationSupport	/* OPTIONAL */;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ReportingPLMN_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_ReportingPLMN;

#ifdef __cplusplus
}
#endif

#endif	/* _ReportingPLMN_H_ */
#include <asn_internal.h>
