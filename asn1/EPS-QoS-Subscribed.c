/*
 * Generated by asn1c-0.9.23 (http://lionet.info/asn1c)
 * From ASN.1 module "MAP-MS-DataTypes"
 * 	found in "../asn1src/MAP-MS-DataTypes.asn"
 * 	`asn1c -gen-PER -fskeletons-copy -fnative-types`
 */

#include "EPS-QoS-Subscribed.h"

static asn_TYPE_member_t asn_MBR_EPS_QoS_Subscribed_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct EPS_QoS_Subscribed, qos_Class_Identifier),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_QoS_Class_Identifier,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"qos-Class-Identifier"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct EPS_QoS_Subscribed, allocation_Retention_Priority),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_Allocation_Retention_Priority,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"allocation-Retention-Priority"
		},
	{ ATF_POINTER, 1, offsetof(struct EPS_QoS_Subscribed, extensionContainer),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ExtensionContainer,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"extensionContainer"
		},
};
static int asn_MAP_EPS_QoS_Subscribed_oms_1[] = { 2 };
static ber_tlv_tag_t asn_DEF_EPS_QoS_Subscribed_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_EPS_QoS_Subscribed_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* qos-Class-Identifier at 1190 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* allocation-Retention-Priority at 1191 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* extensionContainer at 1192 */
};
static asn_SEQUENCE_specifics_t asn_SPC_EPS_QoS_Subscribed_specs_1 = {
	sizeof(struct EPS_QoS_Subscribed),
	offsetof(struct EPS_QoS_Subscribed, _asn_ctx),
	asn_MAP_EPS_QoS_Subscribed_tag2el_1,
	3,	/* Count of tags in the map */
	asn_MAP_EPS_QoS_Subscribed_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	2,	/* Start extensions */
	4	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_EPS_QoS_Subscribed = {
	"EPS-QoS-Subscribed",
	"EPS-QoS-Subscribed",
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
	asn_DEF_EPS_QoS_Subscribed_tags_1,
	sizeof(asn_DEF_EPS_QoS_Subscribed_tags_1)
		/sizeof(asn_DEF_EPS_QoS_Subscribed_tags_1[0]), /* 1 */
	asn_DEF_EPS_QoS_Subscribed_tags_1,	/* Same as above */
	sizeof(asn_DEF_EPS_QoS_Subscribed_tags_1)
		/sizeof(asn_DEF_EPS_QoS_Subscribed_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_EPS_QoS_Subscribed_1,
	3,	/* Elements count */
	&asn_SPC_EPS_QoS_Subscribed_specs_1	/* Additional specs */
};

