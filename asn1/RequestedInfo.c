/*
 * Generated by asn1c-0.9.23 (http://lionet.info/asn1c)
 * From ASN.1 module "MAP-MS-DataTypes"
 * 	found in "../asn1src/MAP-MS-DataTypes.asn"
 * 	`asn1c -gen-PER -fskeletons-copy -fnative-types`
 */

#include "RequestedInfo.h"

static asn_TYPE_member_t asn_MBR_RequestedInfo_1[] = {
	{ ATF_POINTER, 12, offsetof(struct RequestedInfo, locationInformation),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"locationInformation"
		},
	{ ATF_POINTER, 11, offsetof(struct RequestedInfo, subscriberState),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"subscriberState"
		},
	{ ATF_POINTER, 10, offsetof(struct RequestedInfo, extensionContainer),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ExtensionContainer,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"extensionContainer"
		},
	{ ATF_POINTER, 9, offsetof(struct RequestedInfo, currentLocation),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"currentLocation"
		},
	{ ATF_POINTER, 8, offsetof(struct RequestedInfo, requestedDomain),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DomainType,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"requestedDomain"
		},
	{ ATF_POINTER, 7, offsetof(struct RequestedInfo, imei),
		(ASN_TAG_CLASS_CONTEXT | (6 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"imei"
		},
	{ ATF_POINTER, 6, offsetof(struct RequestedInfo, ms_classmark),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"ms-classmark"
		},
	{ ATF_POINTER, 5, offsetof(struct RequestedInfo, mnpRequestedInfo),
		(ASN_TAG_CLASS_CONTEXT | (7 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"mnpRequestedInfo"
		},
	{ ATF_POINTER, 4, offsetof(struct RequestedInfo, locationInformationEPS_Supported),
		(ASN_TAG_CLASS_CONTEXT | (11 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"locationInformationEPS-Supported"
		},
	{ ATF_POINTER, 3, offsetof(struct RequestedInfo, t_adsData),
		(ASN_TAG_CLASS_CONTEXT | (8 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"t-adsData"
		},
	{ ATF_POINTER, 2, offsetof(struct RequestedInfo, requestedNodes),
		(ASN_TAG_CLASS_CONTEXT | (9 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RequestedNodes,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"requestedNodes"
		},
	{ ATF_POINTER, 1, offsetof(struct RequestedInfo, servingNodeIndication),
		(ASN_TAG_CLASS_CONTEXT | (10 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"servingNodeIndication"
		},
};
static int asn_MAP_RequestedInfo_oms_1[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };
static ber_tlv_tag_t asn_DEF_RequestedInfo_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_RequestedInfo_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* locationInformation at 2572 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* subscriberState at 2573 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* extensionContainer at 2574 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* currentLocation at 2576 */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* requestedDomain at 2577 */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 6, 0, 0 }, /* ms-classmark at 2579 */
    { (ASN_TAG_CLASS_CONTEXT | (6 << 2)), 5, 0, 0 }, /* imei at 2578 */
    { (ASN_TAG_CLASS_CONTEXT | (7 << 2)), 7, 0, 0 }, /* mnpRequestedInfo at 2580 */
    { (ASN_TAG_CLASS_CONTEXT | (8 << 2)), 9, 0, 0 }, /* t-adsData at 2582 */
    { (ASN_TAG_CLASS_CONTEXT | (9 << 2)), 10, 0, 0 }, /* requestedNodes at 2583 */
    { (ASN_TAG_CLASS_CONTEXT | (10 << 2)), 11, 0, 0 }, /* servingNodeIndication at 2584 */
    { (ASN_TAG_CLASS_CONTEXT | (11 << 2)), 8, 0, 0 } /* locationInformationEPS-Supported at 2581 */
};
static asn_SEQUENCE_specifics_t asn_SPC_RequestedInfo_specs_1 = {
	sizeof(struct RequestedInfo),
	offsetof(struct RequestedInfo, _asn_ctx),
	asn_MAP_RequestedInfo_tag2el_1,
	12,	/* Count of tags in the map */
	asn_MAP_RequestedInfo_oms_1,	/* Optional members */
	3, 9,	/* Root/Additions */
	2,	/* Start extensions */
	13	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_RequestedInfo = {
	"RequestedInfo",
	"RequestedInfo",
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
	asn_DEF_RequestedInfo_tags_1,
	sizeof(asn_DEF_RequestedInfo_tags_1)
		/sizeof(asn_DEF_RequestedInfo_tags_1[0]), /* 1 */
	asn_DEF_RequestedInfo_tags_1,	/* Same as above */
	sizeof(asn_DEF_RequestedInfo_tags_1)
		/sizeof(asn_DEF_RequestedInfo_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_RequestedInfo_1,
	12,	/* Elements count */
	&asn_SPC_RequestedInfo_specs_1	/* Additional specs */
};

