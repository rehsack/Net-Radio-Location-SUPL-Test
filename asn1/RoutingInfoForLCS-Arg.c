/*
 * Generated by asn1c-0.9.23 (http://lionet.info/asn1c)
 * From ASN.1 module "MAP-LCS-DataTypes"
 * 	found in "../asn1src/MAP-LCS-DataTypes.asn"
 * 	`asn1c -gen-PER -fskeletons-copy -fnative-types`
 */

#include "RoutingInfoForLCS-Arg.h"

static asn_TYPE_member_t asn_MBR_RoutingInfoForLCS_Arg_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct RoutingInfoForLCS_Arg, mlcNumber),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ISDN_AddressString,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"mlcNumber"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RoutingInfoForLCS_Arg, targetMS),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_SubscriberIdentity,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"targetMS"
		},
	{ ATF_POINTER, 1, offsetof(struct RoutingInfoForLCS_Arg, extensionContainer),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ExtensionContainer,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"extensionContainer"
		},
};
static int asn_MAP_RoutingInfoForLCS_Arg_oms_1[] = { 2 };
static ber_tlv_tag_t asn_DEF_RoutingInfoForLCS_Arg_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_RoutingInfoForLCS_Arg_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* mlcNumber at 73 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* targetMS at 74 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* extensionContainer at 75 */
};
static asn_SEQUENCE_specifics_t asn_SPC_RoutingInfoForLCS_Arg_specs_1 = {
	sizeof(struct RoutingInfoForLCS_Arg),
	offsetof(struct RoutingInfoForLCS_Arg, _asn_ctx),
	asn_MAP_RoutingInfoForLCS_Arg_tag2el_1,
	3,	/* Count of tags in the map */
	asn_MAP_RoutingInfoForLCS_Arg_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	2,	/* Start extensions */
	4	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_RoutingInfoForLCS_Arg = {
	"RoutingInfoForLCS-Arg",
	"RoutingInfoForLCS-Arg",
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
	asn_DEF_RoutingInfoForLCS_Arg_tags_1,
	sizeof(asn_DEF_RoutingInfoForLCS_Arg_tags_1)
		/sizeof(asn_DEF_RoutingInfoForLCS_Arg_tags_1[0]), /* 1 */
	asn_DEF_RoutingInfoForLCS_Arg_tags_1,	/* Same as above */
	sizeof(asn_DEF_RoutingInfoForLCS_Arg_tags_1)
		/sizeof(asn_DEF_RoutingInfoForLCS_Arg_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_RoutingInfoForLCS_Arg_1,
	3,	/* Elements count */
	&asn_SPC_RoutingInfoForLCS_Arg_specs_1	/* Additional specs */
};

