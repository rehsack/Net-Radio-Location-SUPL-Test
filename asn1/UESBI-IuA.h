/*
 * Generated by asn1c-0.9.23 (http://lionet.info/asn1c)
 * From ASN.1 module "MAP-MS-DataTypes"
 * 	found in "../asn1src/MAP-MS-DataTypes.asn"
 * 	`asn1c -gen-PER -fskeletons-copy -fnative-types`
 */

#ifndef	_UESBI_IuA_H_
#define	_UESBI_IuA_H_


#include <asn_application.h>

/* Including external dependencies */
#include <BIT_STRING.h>

#ifdef __cplusplus
extern "C" {
#endif

/* UESBI-IuA */
typedef BIT_STRING_t	 UESBI_IuA_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UESBI_IuA;
asn_struct_free_f UESBI_IuA_free;
asn_struct_print_f UESBI_IuA_print;
asn_constr_check_f UESBI_IuA_constraint;
ber_type_decoder_f UESBI_IuA_decode_ber;
der_type_encoder_f UESBI_IuA_encode_der;
xer_type_decoder_f UESBI_IuA_decode_xer;
xer_type_encoder_f UESBI_IuA_encode_xer;
per_type_decoder_f UESBI_IuA_decode_uper;
per_type_encoder_f UESBI_IuA_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _UESBI_IuA_H_ */
#include <asn_internal.h>
