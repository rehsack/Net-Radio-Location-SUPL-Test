/*
 * Generated by asn1c-0.9.23 (http://lionet.info/asn1c)
 * From ASN.1 module "MAP-OM-DataTypes"
 * 	found in "../asn1src/MAP-OM-DataTypes.asn"
 * 	`asn1c -gen-PER -fskeletons-copy -fnative-types`
 */

#ifndef	_MGW_EventList_H_
#define	_MGW_EventList_H_


#include <asn_application.h>

/* Including external dependencies */
#include <BIT_STRING.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum MGW_EventList {
	MGW_EventList_context	= 0
} e_MGW_EventList;

/* MGW-EventList */
typedef BIT_STRING_t	 MGW_EventList_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_MGW_EventList;
asn_struct_free_f MGW_EventList_free;
asn_struct_print_f MGW_EventList_print;
asn_constr_check_f MGW_EventList_constraint;
ber_type_decoder_f MGW_EventList_decode_ber;
der_type_encoder_f MGW_EventList_encode_der;
xer_type_decoder_f MGW_EventList_decode_xer;
xer_type_encoder_f MGW_EventList_encode_xer;
per_type_decoder_f MGW_EventList_decode_uper;
per_type_encoder_f MGW_EventList_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _MGW_EventList_H_ */
#include <asn_internal.h>
