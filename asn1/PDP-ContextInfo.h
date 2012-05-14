/*
 * Generated by asn1c-0.9.23 (http://lionet.info/asn1c)
 * From ASN.1 module "MAP-MS-DataTypes"
 * 	found in "../asn1src/MAP-MS-DataTypes.asn"
 * 	`asn1c -gen-PER -fskeletons-copy -fnative-types`
 */

#ifndef	_PDP_ContextInfo_H_
#define	_PDP_ContextInfo_H_


#include <asn_application.h>

/* Including external dependencies */
#include "ContextId.h"
#include <NULL.h>
#include "PDP-Type.h"
#include "PDP-Address.h"
#include "APN.h"
#include "NSAPI.h"
#include "TransactionId.h"
#include "TEID.h"
#include "GSN-Address.h"
#include "Ext-QoS-Subscribed.h"
#include "GPRSChargingID.h"
#include "ChargingCharacteristics.h"
#include "Ext2-QoS-Subscribed.h"
#include "Ext3-QoS-Subscribed.h"
#include "Ext4-QoS-Subscribed.h"
#include "Ext-PDP-Type.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct ExtensionContainer;

/* PDP-ContextInfo */
typedef struct PDP_ContextInfo {
	ContextId_t	 pdp_ContextIdentifier;
	NULL_t	*pdp_ContextActive	/* OPTIONAL */;
	PDP_Type_t	 pdp_Type;
	PDP_Address_t	*pdp_Address	/* OPTIONAL */;
	APN_t	*apn_Subscribed	/* OPTIONAL */;
	APN_t	*apn_InUse	/* OPTIONAL */;
	NSAPI_t	*nsapi	/* OPTIONAL */;
	TransactionId_t	*transactionId	/* OPTIONAL */;
	TEID_t	*teid_ForGnAndGp	/* OPTIONAL */;
	TEID_t	*teid_ForIu	/* OPTIONAL */;
	GSN_Address_t	*ggsn_Address	/* OPTIONAL */;
	Ext_QoS_Subscribed_t	*qos_Subscribed	/* OPTIONAL */;
	Ext_QoS_Subscribed_t	*qos_Requested	/* OPTIONAL */;
	Ext_QoS_Subscribed_t	*qos_Negotiated	/* OPTIONAL */;
	GPRSChargingID_t	*chargingId	/* OPTIONAL */;
	ChargingCharacteristics_t	*chargingCharacteristics	/* OPTIONAL */;
	GSN_Address_t	*rnc_Address	/* OPTIONAL */;
	struct ExtensionContainer	*extensionContainer	/* OPTIONAL */;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	Ext2_QoS_Subscribed_t	*qos2_Subscribed	/* OPTIONAL */;
	Ext2_QoS_Subscribed_t	*qos2_Requested	/* OPTIONAL */;
	Ext2_QoS_Subscribed_t	*qos2_Negotiated	/* OPTIONAL */;
	Ext3_QoS_Subscribed_t	*qos3_Subscribed	/* OPTIONAL */;
	Ext3_QoS_Subscribed_t	*qos3_Requested	/* OPTIONAL */;
	Ext3_QoS_Subscribed_t	*qos3_Negotiated	/* OPTIONAL */;
	Ext4_QoS_Subscribed_t	*qos4_Subscribed	/* OPTIONAL */;
	Ext4_QoS_Subscribed_t	*qos4_Requested	/* OPTIONAL */;
	Ext4_QoS_Subscribed_t	*qos4_Negotiated	/* OPTIONAL */;
	Ext_PDP_Type_t	*ext_pdp_Type	/* OPTIONAL */;
	PDP_Address_t	*ext_pdp_Address	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} PDP_ContextInfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PDP_ContextInfo;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "ExtensionContainer.h"

#endif	/* _PDP_ContextInfo_H_ */
#include <asn_internal.h>
