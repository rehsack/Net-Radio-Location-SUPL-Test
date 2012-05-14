/*
 * Generated by asn1c-0.9.23 (http://lionet.info/asn1c)
 * From ASN.1 module "MAP-OM-DataTypes"
 * 	found in "../asn1src/MAP-OM-DataTypes.asn"
 * 	`asn1c -gen-PER -fskeletons-copy -fnative-types`
 */

#ifndef	_LoggingDuration_H_
#define	_LoggingDuration_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum LoggingDuration {
	LoggingDuration_d600sec	= 0,
	LoggingDuration_d1200sec	= 1,
	LoggingDuration_d2400sec	= 2,
	LoggingDuration_d3600sec	= 3,
	LoggingDuration_d5400sec	= 4,
	LoggingDuration_d7200sec	= 5
} e_LoggingDuration;

/* LoggingDuration */
typedef long	 LoggingDuration_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_LoggingDuration;
asn_struct_free_f LoggingDuration_free;
asn_struct_print_f LoggingDuration_print;
asn_constr_check_f LoggingDuration_constraint;
ber_type_decoder_f LoggingDuration_decode_ber;
der_type_encoder_f LoggingDuration_encode_der;
xer_type_decoder_f LoggingDuration_decode_xer;
xer_type_encoder_f LoggingDuration_encode_xer;
per_type_decoder_f LoggingDuration_decode_uper;
per_type_encoder_f LoggingDuration_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _LoggingDuration_H_ */
#include <asn_internal.h>
