/*
 * Generated by asn1c-0.9.23 (http://lionet.info/asn1c)
 * From ASN.1 module "MAP-ER-DataTypes"
 * 	found in "../asn1src/MAP-ER-DataTypes.asn"
 * 	`asn1c -gen-PER -fskeletons-copy -fnative-types`
 */

#ifndef	_SM_DeliveryFailureCause_H_
#define	_SM_DeliveryFailureCause_H_


#include <asn_application.h>

/* Including external dependencies */
#include "SM-EnumeratedDeliveryFailureCause.h"
#include "SignalInfo.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct ExtensionContainer;

/* SM-DeliveryFailureCause */
typedef struct SM_DeliveryFailureCause {
	SM_EnumeratedDeliveryFailureCause_t	 sm_EnumeratedDeliveryFailureCause;
	SignalInfo_t	*diagnosticInfo	/* OPTIONAL */;
	struct ExtensionContainer	*extensionContainer	/* OPTIONAL */;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SM_DeliveryFailureCause_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SM_DeliveryFailureCause;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "ExtensionContainer.h"

#endif	/* _SM_DeliveryFailureCause_H_ */
#include <asn_internal.h>
