/*
 * Generated by asn1c-0.9.23 (http://lionet.info/asn1c)
 * From ASN.1 module "MAP-LCS-DataTypes"
 * 	found in "../asn1src/MAP-LCS-DataTypes.asn"
 * 	`asn1c -gen-PER -fskeletons-copy -fnative-types`
 */

#ifndef	_PrivacyCheckRelatedAction_H_
#define	_PrivacyCheckRelatedAction_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum PrivacyCheckRelatedAction {
	PrivacyCheckRelatedAction_allowedWithoutNotification	= 0,
	PrivacyCheckRelatedAction_allowedWithNotification	= 1,
	PrivacyCheckRelatedAction_allowedIfNoResponse	= 2,
	PrivacyCheckRelatedAction_restrictedIfNoResponse	= 3,
	PrivacyCheckRelatedAction_notAllowed	= 4
	/*
	 * Enumeration is extensible
	 */
} e_PrivacyCheckRelatedAction;

/* PrivacyCheckRelatedAction */
typedef long	 PrivacyCheckRelatedAction_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PrivacyCheckRelatedAction;
asn_struct_free_f PrivacyCheckRelatedAction_free;
asn_struct_print_f PrivacyCheckRelatedAction_print;
asn_constr_check_f PrivacyCheckRelatedAction_constraint;
ber_type_decoder_f PrivacyCheckRelatedAction_decode_ber;
der_type_encoder_f PrivacyCheckRelatedAction_encode_der;
xer_type_decoder_f PrivacyCheckRelatedAction_decode_xer;
xer_type_encoder_f PrivacyCheckRelatedAction_encode_xer;
per_type_decoder_f PrivacyCheckRelatedAction_decode_uper;
per_type_encoder_f PrivacyCheckRelatedAction_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _PrivacyCheckRelatedAction_H_ */
#include <asn_internal.h>
