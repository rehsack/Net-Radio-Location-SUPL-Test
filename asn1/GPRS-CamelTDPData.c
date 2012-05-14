/*
 * Generated by asn1c-0.9.23 (http://lionet.info/asn1c)
 * From ASN.1 module "MAP-MS-DataTypes"
 * 	found in "../asn1src/MAP-MS-DataTypes.asn"
 * 	`asn1c -gen-PER -fskeletons-copy -fnative-types`
 */

#include "GPRS-CamelTDPData.h"

static asn_TYPE_member_t asn_MBR_GPRS_CamelTDPData_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct GPRS_CamelTDPData, gprs_TriggerDetectionPoint),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_GPRS_TriggerDetectionPoint,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"gprs-TriggerDetectionPoint"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct GPRS_CamelTDPData, serviceKey),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ServiceKey,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"serviceKey"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct GPRS_CamelTDPData, gsmSCF_Address),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ISDN_AddressString,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"gsmSCF-Address"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct GPRS_CamelTDPData, defaultSessionHandling),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DefaultGPRS_Handling,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"defaultSessionHandling"
		},
	{ ATF_POINTER, 1, offsetof(struct GPRS_CamelTDPData, extensionContainer),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ExtensionContainer,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"extensionContainer"
		},
};
static int asn_MAP_GPRS_CamelTDPData_oms_1[] = { 4 };
static ber_tlv_tag_t asn_DEF_GPRS_CamelTDPData_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_GPRS_CamelTDPData_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* gprs-TriggerDetectionPoint at 1384 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* serviceKey at 1385 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* gsmSCF-Address at 1386 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* defaultSessionHandling at 1387 */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 } /* extensionContainer at 1388 */
};
static asn_SEQUENCE_specifics_t asn_SPC_GPRS_CamelTDPData_specs_1 = {
	sizeof(struct GPRS_CamelTDPData),
	offsetof(struct GPRS_CamelTDPData, _asn_ctx),
	asn_MAP_GPRS_CamelTDPData_tag2el_1,
	5,	/* Count of tags in the map */
	asn_MAP_GPRS_CamelTDPData_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	4,	/* Start extensions */
	6	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_GPRS_CamelTDPData = {
	"GPRS-CamelTDPData",
	"GPRS-CamelTDPData",
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
	asn_DEF_GPRS_CamelTDPData_tags_1,
	sizeof(asn_DEF_GPRS_CamelTDPData_tags_1)
		/sizeof(asn_DEF_GPRS_CamelTDPData_tags_1[0]), /* 1 */
	asn_DEF_GPRS_CamelTDPData_tags_1,	/* Same as above */
	sizeof(asn_DEF_GPRS_CamelTDPData_tags_1)
		/sizeof(asn_DEF_GPRS_CamelTDPData_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_GPRS_CamelTDPData_1,
	5,	/* Elements count */
	&asn_SPC_GPRS_CamelTDPData_specs_1	/* Additional specs */
};

