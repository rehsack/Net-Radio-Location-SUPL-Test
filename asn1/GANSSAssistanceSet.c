/*
 * Generated by asn1c-0.9.23 (http://lionet.info/asn1c)
 * From ASN.1 module "RRLP-Components"
 * 	found in "../asn1src/RRLP-Components.asn"
 * 	`asn1c -gen-PER -fskeletons-copy -fnative-types`
 */

#include "GANSSAssistanceSet.h"

static asn_TYPE_member_t asn_MBR_GANSSAssistanceSet_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct GANSSAssistanceSet, commonGANSSAssistance),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CommonGANSSAssistance,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"commonGANSSAssistance"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct GANSSAssistanceSet, specificGANSSAssistance),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SpecificGANSSAssistance,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"specificGANSSAssistance"
		},
};
static ber_tlv_tag_t asn_DEF_GANSSAssistanceSet_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_GANSSAssistanceSet_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* commonGANSSAssistance at 2348 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* specificGANSSAssistance at 2349 */
};
static asn_SEQUENCE_specifics_t asn_SPC_GANSSAssistanceSet_specs_1 = {
	sizeof(struct GANSSAssistanceSet),
	offsetof(struct GANSSAssistanceSet, _asn_ctx),
	asn_MAP_GANSSAssistanceSet_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	1,	/* Start extensions */
	3	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_GANSSAssistanceSet = {
	"GANSSAssistanceSet",
	"GANSSAssistanceSet",
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
	asn_DEF_GANSSAssistanceSet_tags_1,
	sizeof(asn_DEF_GANSSAssistanceSet_tags_1)
		/sizeof(asn_DEF_GANSSAssistanceSet_tags_1[0]), /* 1 */
	asn_DEF_GANSSAssistanceSet_tags_1,	/* Same as above */
	sizeof(asn_DEF_GANSSAssistanceSet_tags_1)
		/sizeof(asn_DEF_GANSSAssistanceSet_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_GANSSAssistanceSet_1,
	2,	/* Elements count */
	&asn_SPC_GANSSAssistanceSet_specs_1	/* Additional specs */
};

