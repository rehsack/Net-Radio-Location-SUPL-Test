/*
 * Generated by asn1c-0.9.23 (http://lionet.info/asn1c)
 * From ASN.1 module "MAP-ER-DataTypes"
 * 	found in "../asn1src/MAP-ER-DataTypes.asn"
 * 	`asn1c -gen-PER -fskeletons-copy -fnative-types`
 */

#ifndef	_FailureCauseParam_H_
#define	_FailureCauseParam_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum FailureCauseParam {
	FailureCauseParam_limitReachedOnNumberOfConcurrentLocationRequests	= 0
	/*
	 * Enumeration is extensible
	 */
} e_FailureCauseParam;

/* FailureCauseParam */
typedef long	 FailureCauseParam_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_FailureCauseParam;
asn_struct_free_f FailureCauseParam_free;
asn_struct_print_f FailureCauseParam_print;
asn_constr_check_f FailureCauseParam_constraint;
ber_type_decoder_f FailureCauseParam_decode_ber;
der_type_encoder_f FailureCauseParam_encode_der;
xer_type_decoder_f FailureCauseParam_decode_xer;
xer_type_encoder_f FailureCauseParam_encode_xer;
per_type_decoder_f FailureCauseParam_decode_uper;
per_type_encoder_f FailureCauseParam_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _FailureCauseParam_H_ */
#include <asn_internal.h>
