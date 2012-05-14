/*
 * Generated by asn1c-0.9.23 (http://lionet.info/asn1c)
 * From ASN.1 module "RRLP-Components"
 * 	found in "../asn1src/RRLP-Components.asn"
 * 	`asn1c -gen-PER -fskeletons-copy -fnative-types`
 */

#include "ReferenceAssistData.h"

static asn_TYPE_member_t asn_MBR_ReferenceAssistData_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct ReferenceAssistData, bcchCarrier),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BCCHCarrier,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"bcchCarrier"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct ReferenceAssistData, bsic),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BSIC,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"bsic"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct ReferenceAssistData, timeSlotScheme),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TimeSlotScheme,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"timeSlotScheme"
		},
	{ ATF_POINTER, 1, offsetof(struct ReferenceAssistData, btsPosition),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BTSPosition,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"btsPosition"
		},
};
static int asn_MAP_ReferenceAssistData_oms_1[] = { 3 };
static ber_tlv_tag_t asn_DEF_ReferenceAssistData_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_ReferenceAssistData_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* bcchCarrier at 171 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* bsic at 172 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* timeSlotScheme at 173 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* btsPosition at 174 */
};
static asn_SEQUENCE_specifics_t asn_SPC_ReferenceAssistData_specs_1 = {
	sizeof(struct ReferenceAssistData),
	offsetof(struct ReferenceAssistData, _asn_ctx),
	asn_MAP_ReferenceAssistData_tag2el_1,
	4,	/* Count of tags in the map */
	asn_MAP_ReferenceAssistData_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_ReferenceAssistData = {
	"ReferenceAssistData",
	"ReferenceAssistData",
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
	asn_DEF_ReferenceAssistData_tags_1,
	sizeof(asn_DEF_ReferenceAssistData_tags_1)
		/sizeof(asn_DEF_ReferenceAssistData_tags_1[0]), /* 1 */
	asn_DEF_ReferenceAssistData_tags_1,	/* Same as above */
	sizeof(asn_DEF_ReferenceAssistData_tags_1)
		/sizeof(asn_DEF_ReferenceAssistData_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_ReferenceAssistData_1,
	4,	/* Elements count */
	&asn_SPC_ReferenceAssistData_specs_1	/* Additional specs */
};

