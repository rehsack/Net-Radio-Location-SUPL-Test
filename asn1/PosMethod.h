/*
 * Generated by asn1c-0.9.23 (http://lionet.info/asn1c)
 * From ASN.1 module "ULP-Components"
 * 	found in "../asn1src/ULP-Components.asn"
 * 	`asn1c -gen-PER -fskeletons-copy -fnative-types`
 */

#ifndef	_PosMethod_H_
#define	_PosMethod_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum PosMethod {
	PosMethod_agpsSETassisted	= 0,
	PosMethod_agpsSETbased	= 1,
	PosMethod_agpsSETassistedpref	= 2,
	PosMethod_agpsSETbasedpref	= 3,
	PosMethod_autonomousGPS	= 4,
	PosMethod_aFLT	= 5,
	PosMethod_eCID	= 6,
	PosMethod_eOTD	= 7,
	PosMethod_oTDOA	= 8,
	PosMethod_noPosition	= 9
	/*
	 * Enumeration is extensible
	 */
} e_PosMethod;

/* PosMethod */
typedef long	 PosMethod_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PosMethod;
asn_struct_free_f PosMethod_free;
asn_struct_print_f PosMethod_print;
asn_constr_check_f PosMethod_constraint;
ber_type_decoder_f PosMethod_decode_ber;
der_type_encoder_f PosMethod_encode_der;
xer_type_decoder_f PosMethod_decode_xer;
xer_type_encoder_f PosMethod_encode_xer;
per_type_decoder_f PosMethod_decode_uper;
per_type_encoder_f PosMethod_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _PosMethod_H_ */
#include <asn_internal.h>
