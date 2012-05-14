/*
 * Generated by asn1c-0.9.23 (http://lionet.info/asn1c)
 * From ASN.1 module "MAP-MS-DataTypes"
 * 	found in "../asn1src/MAP-MS-DataTypes.asn"
 * 	`asn1c -gen-PER -fskeletons-copy -fnative-types`
 */

#include "PurgeMS-Arg.h"

static asn_TYPE_member_t asn_MBR_PurgeMS_Arg_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct PurgeMS_Arg, imsi),
		(ASN_TAG_CLASS_UNIVERSAL | (4 << 2)),
		0,
		&asn_DEF_IMSI,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"imsi"
		},
	{ ATF_POINTER, 3, offsetof(struct PurgeMS_Arg, vlr_Number),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ISDN_AddressString,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"vlr-Number"
		},
	{ ATF_POINTER, 2, offsetof(struct PurgeMS_Arg, sgsn_Number),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ISDN_AddressString,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"sgsn-Number"
		},
	{ ATF_POINTER, 1, offsetof(struct PurgeMS_Arg, extensionContainer),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_ExtensionContainer,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"extensionContainer"
		},
};
static int asn_MAP_PurgeMS_Arg_oms_1[] = { 1, 2, 3 };
static ber_tlv_tag_t asn_DEF_PurgeMS_Arg_tags_1[] = {
	(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_PurgeMS_Arg_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (4 << 2)), 0, 0, 0 }, /* imsi at 361 */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 3, 0, 0 }, /* extensionContainer at 364 */
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 1, 0, 0 }, /* vlr-Number at 362 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 2, 0, 0 } /* sgsn-Number at 363 */
};
static asn_SEQUENCE_specifics_t asn_SPC_PurgeMS_Arg_specs_1 = {
	sizeof(struct PurgeMS_Arg),
	offsetof(struct PurgeMS_Arg, _asn_ctx),
	asn_MAP_PurgeMS_Arg_tag2el_1,
	4,	/* Count of tags in the map */
	asn_MAP_PurgeMS_Arg_oms_1,	/* Optional members */
	3, 0,	/* Root/Additions */
	3,	/* Start extensions */
	5	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_PurgeMS_Arg = {
	"PurgeMS-Arg",
	"PurgeMS-Arg",
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
	asn_DEF_PurgeMS_Arg_tags_1,
	sizeof(asn_DEF_PurgeMS_Arg_tags_1)
		/sizeof(asn_DEF_PurgeMS_Arg_tags_1[0]) - 1, /* 1 */
	asn_DEF_PurgeMS_Arg_tags_1,	/* Same as above */
	sizeof(asn_DEF_PurgeMS_Arg_tags_1)
		/sizeof(asn_DEF_PurgeMS_Arg_tags_1[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_PurgeMS_Arg_1,
	4,	/* Elements count */
	&asn_SPC_PurgeMS_Arg_specs_1	/* Additional specs */
};

