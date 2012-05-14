/*
 * Generated by asn1c-0.9.23 (http://lionet.info/asn1c)
 * From ASN.1 module "MAP-MS-DataTypes"
 * 	found in "../asn1src/MAP-MS-DataTypes.asn"
 * 	`asn1c -gen-PER -fskeletons-copy -fnative-types`
 */

#ifndef	_RegionalSubscriptionResponse_H_
#define	_RegionalSubscriptionResponse_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum RegionalSubscriptionResponse {
	RegionalSubscriptionResponse_networkNode_AreaRestricted	= 0,
	RegionalSubscriptionResponse_tooManyZoneCodes	= 1,
	RegionalSubscriptionResponse_zoneCodesConflict	= 2,
	RegionalSubscriptionResponse_regionalSubscNotSupported	= 3
} e_RegionalSubscriptionResponse;

/* RegionalSubscriptionResponse */
typedef long	 RegionalSubscriptionResponse_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RegionalSubscriptionResponse;
asn_struct_free_f RegionalSubscriptionResponse_free;
asn_struct_print_f RegionalSubscriptionResponse_print;
asn_constr_check_f RegionalSubscriptionResponse_constraint;
ber_type_decoder_f RegionalSubscriptionResponse_decode_ber;
der_type_encoder_f RegionalSubscriptionResponse_encode_der;
xer_type_decoder_f RegionalSubscriptionResponse_decode_xer;
xer_type_encoder_f RegionalSubscriptionResponse_encode_xer;
per_type_decoder_f RegionalSubscriptionResponse_decode_uper;
per_type_encoder_f RegionalSubscriptionResponse_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _RegionalSubscriptionResponse_H_ */
#include <asn_internal.h>
