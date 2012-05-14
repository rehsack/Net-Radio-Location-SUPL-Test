/*
 * Generated by asn1c-0.9.23 (http://lionet.info/asn1c)
 * From ASN.1 module "RRLP-Components"
 * 	found in "../asn1src/RRLP-Components.asn"
 * 	`asn1c -gen-PER -fskeletons-copy -fnative-types`
 */

#ifndef	_OTD_FirstSetMsrs_H_
#define	_OTD_FirstSetMsrs_H_


#include <asn_application.h>

/* Including external dependencies */
#include "OTD-MeasurementWithID.h"

#ifdef __cplusplus
extern "C" {
#endif

/* OTD-FirstSetMsrs */
typedef OTD_MeasurementWithID_t	 OTD_FirstSetMsrs_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_OTD_FirstSetMsrs;
asn_struct_free_f OTD_FirstSetMsrs_free;
asn_struct_print_f OTD_FirstSetMsrs_print;
asn_constr_check_f OTD_FirstSetMsrs_constraint;
ber_type_decoder_f OTD_FirstSetMsrs_decode_ber;
der_type_encoder_f OTD_FirstSetMsrs_encode_der;
xer_type_decoder_f OTD_FirstSetMsrs_decode_xer;
xer_type_encoder_f OTD_FirstSetMsrs_encode_xer;
per_type_decoder_f OTD_FirstSetMsrs_decode_uper;
per_type_encoder_f OTD_FirstSetMsrs_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _OTD_FirstSetMsrs_H_ */
#include <asn_internal.h>
