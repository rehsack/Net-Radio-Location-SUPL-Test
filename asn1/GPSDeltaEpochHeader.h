/*
 * Generated by asn1c-0.9.23 (http://lionet.info/asn1c)
 * From ASN.1 module "RRLP-Components"
 * 	found in "../asn1src/RRLP-Components.asn"
 * 	`asn1c -gen-PER -fskeletons-copy -fnative-types`
 */

#ifndef	_GPSDeltaEpochHeader_H_
#define	_GPSDeltaEpochHeader_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeInteger.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct GPSEphemerisDeltaBitSizes;
struct GPSEphemerisDeltaScales;

/* GPSDeltaEpochHeader */
typedef struct GPSDeltaEpochHeader {
	long	*validityPeriod	/* OPTIONAL */;
	struct GPSEphemerisDeltaBitSizes	*ephemerisDeltaSizes	/* OPTIONAL */;
	struct GPSEphemerisDeltaScales	*ephemerisDeltaScales	/* OPTIONAL */;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} GPSDeltaEpochHeader_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_GPSDeltaEpochHeader;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "GPSEphemerisDeltaBitSizes.h"
#include "GPSEphemerisDeltaScales.h"

#endif	/* _GPSDeltaEpochHeader_H_ */
#include <asn_internal.h>
