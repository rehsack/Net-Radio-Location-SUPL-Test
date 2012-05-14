/*
 * Generated by asn1c-0.9.23 (http://lionet.info/asn1c)
 * From ASN.1 module "MAP-SM-DataTypes"
 * 	found in "../asn1src/MAP-SM-DataTypes.asn"
 * 	`asn1c -gen-PER -fskeletons-copy -fnative-types`
 */

#ifndef	_MW_Status_H_
#define	_MW_Status_H_


#include <asn_application.h>

/* Including external dependencies */
#include <BIT_STRING.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum MW_Status {
	MW_Status_sc_AddressNotIncluded	= 0,
	MW_Status_mnrf_Set	= 1,
	MW_Status_mcef_Set	= 2,
	MW_Status_mnrg_Set	= 3
} e_MW_Status;

/* MW-Status */
typedef BIT_STRING_t	 MW_Status_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_MW_Status;
asn_struct_free_f MW_Status_free;
asn_struct_print_f MW_Status_print;
asn_constr_check_f MW_Status_constraint;
ber_type_decoder_f MW_Status_decode_ber;
der_type_encoder_f MW_Status_encode_der;
xer_type_decoder_f MW_Status_decode_xer;
xer_type_encoder_f MW_Status_encode_xer;
per_type_decoder_f MW_Status_decode_uper;
per_type_encoder_f MW_Status_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _MW_Status_H_ */
#include <asn_internal.h>
