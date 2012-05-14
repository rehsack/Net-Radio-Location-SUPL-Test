/*
 * Generated by asn1c-0.9.23 (http://lionet.info/asn1c)
 * From ASN.1 module "RRLP-Components"
 * 	found in "../asn1src/RRLP-Components.asn"
 * 	`asn1c -gen-PER -fskeletons-copy -fnative-types`
 */

#include "PosCapabilities.h"

static asn_TYPE_member_t asn_MBR_PosCapabilities_1[] = {
	{ ATF_POINTER, 3, offsetof(struct PosCapabilities, nonGANSSpositionMethods),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NonGANSSPositionMethods,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"nonGANSSpositionMethods"
		},
	{ ATF_POINTER, 2, offsetof(struct PosCapabilities, gANSSPositionMethods),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_GANSSPositionMethods,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"gANSSPositionMethods"
		},
	{ ATF_POINTER, 1, offsetof(struct PosCapabilities, multipleMeasurementSets),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MultipleMeasurementSets,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"multipleMeasurementSets"
		},
};
static int asn_MAP_PosCapabilities_oms_1[] = { 0, 1, 2 };
static ber_tlv_tag_t asn_DEF_PosCapabilities_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_PosCapabilities_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* nonGANSSpositionMethods at 2259 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* gANSSPositionMethods at 2262 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* multipleMeasurementSets at 2266 */
};
static asn_SEQUENCE_specifics_t asn_SPC_PosCapabilities_specs_1 = {
	sizeof(struct PosCapabilities),
	offsetof(struct PosCapabilities, _asn_ctx),
	asn_MAP_PosCapabilities_tag2el_1,
	3,	/* Count of tags in the map */
	asn_MAP_PosCapabilities_oms_1,	/* Optional members */
	3, 0,	/* Root/Additions */
	2,	/* Start extensions */
	4	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_PosCapabilities = {
	"PosCapabilities",
	"PosCapabilities",
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
	asn_DEF_PosCapabilities_tags_1,
	sizeof(asn_DEF_PosCapabilities_tags_1)
		/sizeof(asn_DEF_PosCapabilities_tags_1[0]), /* 1 */
	asn_DEF_PosCapabilities_tags_1,	/* Same as above */
	sizeof(asn_DEF_PosCapabilities_tags_1)
		/sizeof(asn_DEF_PosCapabilities_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_PosCapabilities_1,
	3,	/* Elements count */
	&asn_SPC_PosCapabilities_specs_1	/* Additional specs */
};

