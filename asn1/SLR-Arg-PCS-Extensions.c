/*
 * Generated by asn1c-0.9.23 (http://lionet.info/asn1c)
 * From ASN.1 module "MAP-ExtensionDataTypes"
 * 	found in "../asn1src/MAP-ExtensionDataTypes.asn"
 * 	`asn1c -gen-PER -fskeletons-copy -fnative-types`
 */

#include "SLR-Arg-PCS-Extensions.h"

static asn_TYPE_member_t asn_MBR_SLR_Arg_PCS_Extensions_1[] = {
	{ ATF_POINTER, 1, offsetof(struct SLR_Arg_PCS_Extensions, na_ESRK_Request),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"na-ESRK-Request"
		},
};
static int asn_MAP_SLR_Arg_PCS_Extensions_oms_1[] = { 0 };
static ber_tlv_tag_t asn_DEF_SLR_Arg_PCS_Extensions_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_SLR_Arg_PCS_Extensions_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* na-ESRK-Request at 63 */
};
static asn_SEQUENCE_specifics_t asn_SPC_SLR_Arg_PCS_Extensions_specs_1 = {
	sizeof(struct SLR_Arg_PCS_Extensions),
	offsetof(struct SLR_Arg_PCS_Extensions, _asn_ctx),
	asn_MAP_SLR_Arg_PCS_Extensions_tag2el_1,
	1,	/* Count of tags in the map */
	asn_MAP_SLR_Arg_PCS_Extensions_oms_1,	/* Optional members */
	0, 1,	/* Root/Additions */
	-1,	/* Start extensions */
	2	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_SLR_Arg_PCS_Extensions = {
	"SLR-Arg-PCS-Extensions",
	"SLR-Arg-PCS-Extensions",
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
	asn_DEF_SLR_Arg_PCS_Extensions_tags_1,
	sizeof(asn_DEF_SLR_Arg_PCS_Extensions_tags_1)
		/sizeof(asn_DEF_SLR_Arg_PCS_Extensions_tags_1[0]), /* 1 */
	asn_DEF_SLR_Arg_PCS_Extensions_tags_1,	/* Same as above */
	sizeof(asn_DEF_SLR_Arg_PCS_Extensions_tags_1)
		/sizeof(asn_DEF_SLR_Arg_PCS_Extensions_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_SLR_Arg_PCS_Extensions_1,
	1,	/* Elements count */
	&asn_SPC_SLR_Arg_PCS_Extensions_specs_1	/* Additional specs */
};

