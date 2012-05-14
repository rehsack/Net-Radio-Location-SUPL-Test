/*
 * Generated by asn1c-0.9.23 (http://lionet.info/asn1c)
 * From ASN.1 module "MAP-MS-DataTypes"
 * 	found in "../asn1src/MAP-MS-DataTypes.asn"
 * 	`asn1c -gen-PER -fskeletons-copy -fnative-types`
 */

#ifndef	_InterCUG_Restrictions_H_
#define	_InterCUG_Restrictions_H_


#include <asn_application.h>

/* Including external dependencies */
#include <OCTET_STRING.h>

#ifdef __cplusplus
extern "C" {
#endif

/* InterCUG-Restrictions */
typedef OCTET_STRING_t	 InterCUG_Restrictions_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_InterCUG_Restrictions;
asn_struct_free_f InterCUG_Restrictions_free;
asn_struct_print_f InterCUG_Restrictions_print;
asn_constr_check_f InterCUG_Restrictions_constraint;
ber_type_decoder_f InterCUG_Restrictions_decode_ber;
der_type_encoder_f InterCUG_Restrictions_encode_der;
xer_type_decoder_f InterCUG_Restrictions_decode_xer;
xer_type_encoder_f InterCUG_Restrictions_encode_xer;
per_type_decoder_f InterCUG_Restrictions_decode_uper;
per_type_encoder_f InterCUG_Restrictions_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _InterCUG_Restrictions_H_ */
#include <asn_internal.h>
