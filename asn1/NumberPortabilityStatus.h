/*
 * Generated by asn1c-0.9.23 (http://lionet.info/asn1c)
 * From ASN.1 module "MAP-MS-DataTypes"
 * 	found in "../asn1src/MAP-MS-DataTypes.asn"
 * 	`asn1c -gen-PER -fskeletons-copy -fnative-types`
 */

#ifndef	_NumberPortabilityStatus_H_
#define	_NumberPortabilityStatus_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum NumberPortabilityStatus {
	NumberPortabilityStatus_notKnownToBePorted	= 0,
	NumberPortabilityStatus_ownNumberPortedOut	= 1,
	NumberPortabilityStatus_foreignNumberPortedToForeignNetwork	= 2,
	/*
	 * Enumeration is extensible
	 */
	NumberPortabilityStatus_ownNumberNotPortedOut	= 4,
	NumberPortabilityStatus_foreignNumberPortedIn	= 5
} e_NumberPortabilityStatus;

/* NumberPortabilityStatus */
typedef long	 NumberPortabilityStatus_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_NumberPortabilityStatus;
asn_struct_free_f NumberPortabilityStatus_free;
asn_struct_print_f NumberPortabilityStatus_print;
asn_constr_check_f NumberPortabilityStatus_constraint;
ber_type_decoder_f NumberPortabilityStatus_decode_ber;
der_type_encoder_f NumberPortabilityStatus_encode_der;
xer_type_decoder_f NumberPortabilityStatus_decode_xer;
xer_type_encoder_f NumberPortabilityStatus_encode_xer;
per_type_decoder_f NumberPortabilityStatus_decode_uper;
per_type_encoder_f NumberPortabilityStatus_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _NumberPortabilityStatus_H_ */
#include <asn_internal.h>
