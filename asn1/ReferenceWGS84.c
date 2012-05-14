/*
 * Generated by asn1c-0.9.23 (http://lionet.info/asn1c)
 * From ASN.1 module "RRLP-Components"
 * 	found in "../asn1src/RRLP-Components.asn"
 * 	`asn1c -gen-PER -fskeletons-copy -fnative-types`
 */

#include "ReferenceWGS84.h"

static asn_TYPE_member_t asn_MBR_ReferenceWGS84_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct ReferenceWGS84, relativeNorth),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RelDistance,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"relativeNorth"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct ReferenceWGS84, relativeEast),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RelDistance,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"relativeEast"
		},
	{ ATF_POINTER, 1, offsetof(struct ReferenceWGS84, relativeAlt),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RelativeAlt,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"relativeAlt"
		},
};
static int asn_MAP_ReferenceWGS84_oms_1[] = { 2 };
static ber_tlv_tag_t asn_DEF_ReferenceWGS84_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_ReferenceWGS84_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* relativeNorth at 260 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* relativeEast at 261 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* relativeAlt at 263 */
};
static asn_SEQUENCE_specifics_t asn_SPC_ReferenceWGS84_specs_1 = {
	sizeof(struct ReferenceWGS84),
	offsetof(struct ReferenceWGS84, _asn_ctx),
	asn_MAP_ReferenceWGS84_tag2el_1,
	3,	/* Count of tags in the map */
	asn_MAP_ReferenceWGS84_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_ReferenceWGS84 = {
	"ReferenceWGS84",
	"ReferenceWGS84",
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
	asn_DEF_ReferenceWGS84_tags_1,
	sizeof(asn_DEF_ReferenceWGS84_tags_1)
		/sizeof(asn_DEF_ReferenceWGS84_tags_1[0]), /* 1 */
	asn_DEF_ReferenceWGS84_tags_1,	/* Same as above */
	sizeof(asn_DEF_ReferenceWGS84_tags_1)
		/sizeof(asn_DEF_ReferenceWGS84_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_ReferenceWGS84_1,
	3,	/* Elements count */
	&asn_SPC_ReferenceWGS84_specs_1	/* Additional specs */
};

