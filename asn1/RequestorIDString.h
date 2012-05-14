/*
 * Generated by asn1c-0.9.23 (http://lionet.info/asn1c)
 * From ASN.1 module "MAP-LCS-DataTypes"
 * 	found in "../asn1src/MAP-LCS-DataTypes.asn"
 * 	`asn1c -gen-PER -fskeletons-copy -fnative-types`
 */

#ifndef	_RequestorIDString_H_
#define	_RequestorIDString_H_


#include <asn_application.h>

/* Including external dependencies */
#include "USSD-String.h"

#ifdef __cplusplus
extern "C" {
#endif

/* RequestorIDString */
typedef USSD_String_t	 RequestorIDString_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RequestorIDString;
asn_struct_free_f RequestorIDString_free;
asn_struct_print_f RequestorIDString_print;
asn_constr_check_f RequestorIDString_constraint;
ber_type_decoder_f RequestorIDString_decode_ber;
der_type_encoder_f RequestorIDString_encode_der;
xer_type_decoder_f RequestorIDString_decode_xer;
xer_type_encoder_f RequestorIDString_encode_xer;
per_type_decoder_f RequestorIDString_decode_uper;
per_type_encoder_f RequestorIDString_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _RequestorIDString_H_ */
#include <asn_internal.h>
