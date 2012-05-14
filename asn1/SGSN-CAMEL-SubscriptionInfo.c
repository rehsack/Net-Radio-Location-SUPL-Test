/*
 * Generated by asn1c-0.9.23 (http://lionet.info/asn1c)
 * From ASN.1 module "MAP-MS-DataTypes"
 * 	found in "../asn1src/MAP-MS-DataTypes.asn"
 * 	`asn1c -gen-PER -fskeletons-copy -fnative-types`
 */

#include "SGSN-CAMEL-SubscriptionInfo.h"

static asn_TYPE_member_t asn_MBR_SGSN_CAMEL_SubscriptionInfo_1[] = {
	{ ATF_POINTER, 6, offsetof(struct SGSN_CAMEL_SubscriptionInfo, gprs_CSI),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_GPRS_CSI,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"gprs-CSI"
		},
	{ ATF_POINTER, 5, offsetof(struct SGSN_CAMEL_SubscriptionInfo, mo_sms_CSI),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SMS_CSI,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"mo-sms-CSI"
		},
	{ ATF_POINTER, 4, offsetof(struct SGSN_CAMEL_SubscriptionInfo, extensionContainer),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ExtensionContainer,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"extensionContainer"
		},
	{ ATF_POINTER, 3, offsetof(struct SGSN_CAMEL_SubscriptionInfo, mt_sms_CSI),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SMS_CSI,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"mt-sms-CSI"
		},
	{ ATF_POINTER, 2, offsetof(struct SGSN_CAMEL_SubscriptionInfo, mt_smsCAMELTDP_CriteriaList),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MT_smsCAMELTDP_CriteriaList,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"mt-smsCAMELTDP-CriteriaList"
		},
	{ ATF_POINTER, 1, offsetof(struct SGSN_CAMEL_SubscriptionInfo, mg_csi),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MG_CSI,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"mg-csi"
		},
};
static int asn_MAP_SGSN_CAMEL_SubscriptionInfo_oms_1[] = { 0, 1, 2, 3, 4, 5 };
static ber_tlv_tag_t asn_DEF_SGSN_CAMEL_SubscriptionInfo_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_SGSN_CAMEL_SubscriptionInfo_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* gprs-CSI at 1355 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* mo-sms-CSI at 1356 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* extensionContainer at 1357 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* mt-sms-CSI at 1359 */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* mt-smsCAMELTDP-CriteriaList at 1360 */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 } /* mg-csi at 1361 */
};
static asn_SEQUENCE_specifics_t asn_SPC_SGSN_CAMEL_SubscriptionInfo_specs_1 = {
	sizeof(struct SGSN_CAMEL_SubscriptionInfo),
	offsetof(struct SGSN_CAMEL_SubscriptionInfo, _asn_ctx),
	asn_MAP_SGSN_CAMEL_SubscriptionInfo_tag2el_1,
	6,	/* Count of tags in the map */
	asn_MAP_SGSN_CAMEL_SubscriptionInfo_oms_1,	/* Optional members */
	3, 3,	/* Root/Additions */
	2,	/* Start extensions */
	7	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_SGSN_CAMEL_SubscriptionInfo = {
	"SGSN-CAMEL-SubscriptionInfo",
	"SGSN-CAMEL-SubscriptionInfo",
	SEQUENCE_free,
	SEQUENCE_print,
	SEQUENCE_constraint,
	SEQUENCE_decode_ber,
	SEQUENCE_encode_der,
	SEQUENCE_decode_xer,
	SEQUENCE_encode_xer,
	SEQUENCE_decode_uper,
	SEQUENCE_encode_uper,
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_SGSN_CAMEL_SubscriptionInfo_tags_1,
	sizeof(asn_DEF_SGSN_CAMEL_SubscriptionInfo_tags_1)
		/sizeof(asn_DEF_SGSN_CAMEL_SubscriptionInfo_tags_1[0]), /* 1 */
	asn_DEF_SGSN_CAMEL_SubscriptionInfo_tags_1,	/* Same as above */
	sizeof(asn_DEF_SGSN_CAMEL_SubscriptionInfo_tags_1)
		/sizeof(asn_DEF_SGSN_CAMEL_SubscriptionInfo_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_SGSN_CAMEL_SubscriptionInfo_1,
	6,	/* Elements count */
	&asn_SPC_SGSN_CAMEL_SubscriptionInfo_specs_1	/* Additional specs */
};

