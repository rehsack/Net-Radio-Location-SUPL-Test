/*
 * Generated by asn1c-0.9.23 (http://lionet.info/asn1c)
 * From ASN.1 module "SUPL-START"
 * 	found in "../asn1src/SUPL-START.asn"
 * 	`asn1c -gen-PER -fskeletons-copy -fnative-types`
 */

#ifndef	_SUPLSTART_H_
#define	_SUPLSTART_H_


#include <asn_application.h>

/* Including external dependencies */
#include "SETCapabilities.h"
#include "LocationId.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct QoP;

/* SUPLSTART */
typedef struct SUPLSTART {
	SETCapabilities_t	 sETCapabilities;
	LocationId_t	 locationId;
	struct QoP	*qoP	/* OPTIONAL */;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SUPLSTART_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SUPLSTART;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "QoP.h"

#endif	/* _SUPLSTART_H_ */
#include <asn_internal.h>
