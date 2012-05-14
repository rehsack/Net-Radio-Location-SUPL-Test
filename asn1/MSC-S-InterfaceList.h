/*
 * Generated by asn1c-0.9.23 (http://lionet.info/asn1c)
 * From ASN.1 module "MAP-OM-DataTypes"
 * 	found in "../asn1src/MAP-OM-DataTypes.asn"
 * 	`asn1c -gen-PER -fskeletons-copy -fnative-types`
 */

#ifndef	_MSC_S_InterfaceList_H_
#define	_MSC_S_InterfaceList_H_


#include <asn_application.h>

/* Including external dependencies */
#include <BIT_STRING.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum MSC_S_InterfaceList {
	MSC_S_InterfaceList_a	= 0,
	MSC_S_InterfaceList_iu	= 1,
	MSC_S_InterfaceList_mc	= 2,
	MSC_S_InterfaceList_map_g	= 3,
	MSC_S_InterfaceList_map_b	= 4,
	MSC_S_InterfaceList_map_e	= 5,
	MSC_S_InterfaceList_map_f	= 6,
	MSC_S_InterfaceList_cap	= 7,
	MSC_S_InterfaceList_map_d	= 8,
	MSC_S_InterfaceList_map_c	= 9
} e_MSC_S_InterfaceList;

/* MSC-S-InterfaceList */
typedef BIT_STRING_t	 MSC_S_InterfaceList_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_MSC_S_InterfaceList;
asn_struct_free_f MSC_S_InterfaceList_free;
asn_struct_print_f MSC_S_InterfaceList_print;
asn_constr_check_f MSC_S_InterfaceList_constraint;
ber_type_decoder_f MSC_S_InterfaceList_decode_ber;
der_type_encoder_f MSC_S_InterfaceList_encode_der;
xer_type_decoder_f MSC_S_InterfaceList_decode_xer;
xer_type_encoder_f MSC_S_InterfaceList_encode_xer;
per_type_decoder_f MSC_S_InterfaceList_decode_uper;
per_type_encoder_f MSC_S_InterfaceList_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _MSC_S_InterfaceList_H_ */
#include <asn_internal.h>
