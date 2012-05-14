/*
 * Generated by asn1c-0.9.23 (http://lionet.info/asn1c)
 * From ASN.1 module "RRLP-Components"
 * 	found in "../asn1src/RRLP-Components.asn"
 * 	`asn1c -gen-PER -fskeletons-copy -fnative-types`
 */

#ifndef	_GPS_MsrSetElement_H_
#define	_GPS_MsrSetElement_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeInteger.h>
#include "GPSTOW24b.h"
#include "SeqOfGPS-MsrElement.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* GPS-MsrSetElement */
typedef struct GPS_MsrSetElement {
	long	*refFrame	/* OPTIONAL */;
	GPSTOW24b_t	 gpsTOW;
	SeqOfGPS_MsrElement_t	 gps_msrList;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} GPS_MsrSetElement_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_GPS_MsrSetElement;

#ifdef __cplusplus
}
#endif

#endif	/* _GPS_MsrSetElement_H_ */
#include <asn_internal.h>
