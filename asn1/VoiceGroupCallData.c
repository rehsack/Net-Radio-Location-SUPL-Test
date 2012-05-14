/*
 * Generated by asn1c-0.9.23 (http://lionet.info/asn1c)
 * From ASN.1 module "MAP-MS-DataTypes"
 * 	found in "../asn1src/MAP-MS-DataTypes.asn"
 * 	`asn1c -gen-PER -fskeletons-copy -fnative-types`
 */

#include "VoiceGroupCallData.h"

static asn_TYPE_member_t asn_MBR_VoiceGroupCallData_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct VoiceGroupCallData, groupId),
		(ASN_TAG_CLASS_UNIVERSAL | (4 << 2)),
		0,
		&asn_DEF_GroupId,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"groupId"
		},
	{ ATF_POINTER, 4, offsetof(struct VoiceGroupCallData, extensionContainer),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_ExtensionContainer,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"extensionContainer"
		},
	{ ATF_POINTER, 3, offsetof(struct VoiceGroupCallData, additionalSubscriptions),
		(ASN_TAG_CLASS_UNIVERSAL | (3 << 2)),
		0,
		&asn_DEF_AdditionalSubscriptions,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"additionalSubscriptions"
		},
	{ ATF_POINTER, 2, offsetof(struct VoiceGroupCallData, additionalInfo),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_AdditionalInfo,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"additionalInfo"
		},
	{ ATF_POINTER, 1, offsetof(struct VoiceGroupCallData, longGroupId),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_Long_GroupId,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"longGroupId"
		},
};
static int asn_MAP_VoiceGroupCallData_oms_1[] = { 1, 2, 3, 4 };
static ber_tlv_tag_t asn_DEF_VoiceGroupCallData_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_VoiceGroupCallData_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (3 << 2)), 2, 0, 0 }, /* additionalSubscriptions at 2437 */
    { (ASN_TAG_CLASS_UNIVERSAL | (4 << 2)), 0, 0, 0 }, /* groupId at 2433 */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 1, 0, 0 }, /* extensionContainer at 2435 */
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 3, 0, 0 }, /* additionalInfo at 2438 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 4, 0, 0 } /* longGroupId at 2439 */
};
static asn_SEQUENCE_specifics_t asn_SPC_VoiceGroupCallData_specs_1 = {
	sizeof(struct VoiceGroupCallData),
	offsetof(struct VoiceGroupCallData, _asn_ctx),
	asn_MAP_VoiceGroupCallData_tag2el_1,
	5,	/* Count of tags in the map */
	asn_MAP_VoiceGroupCallData_oms_1,	/* Optional members */
	1, 3,	/* Root/Additions */
	1,	/* Start extensions */
	6	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_VoiceGroupCallData = {
	"VoiceGroupCallData",
	"VoiceGroupCallData",
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
	asn_DEF_VoiceGroupCallData_tags_1,
	sizeof(asn_DEF_VoiceGroupCallData_tags_1)
		/sizeof(asn_DEF_VoiceGroupCallData_tags_1[0]), /* 1 */
	asn_DEF_VoiceGroupCallData_tags_1,	/* Same as above */
	sizeof(asn_DEF_VoiceGroupCallData_tags_1)
		/sizeof(asn_DEF_VoiceGroupCallData_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_VoiceGroupCallData_1,
	5,	/* Elements count */
	&asn_SPC_VoiceGroupCallData_specs_1	/* Additional specs */
};

