/*
 * Generated by asn1c-0.9.23 (http://lionet.info/asn1c)
 * From ASN.1 module "RRLP-Components"
 * 	found in "../asn1src/RRLP-Components.asn"
 * 	`asn1c -gen-PER -fskeletons-copy -fnative-types`
 */

#include "GANSSReferenceTime-R10-Ext.h"

static int
memb_ganssDayCycleNumber_constraint_1(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 7)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_per_constraints_t asn_PER_memb_ganssDayCycleNumber_constr_2 = {
	{ APC_CONSTRAINED,	 3,  3,  0,  7 }	/* (0..7) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_GANSSReferenceTime_R10_Ext_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct GANSSReferenceTime_R10_Ext, ganssDayCycleNumber),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		memb_ganssDayCycleNumber_constraint_1,
		&asn_PER_memb_ganssDayCycleNumber_constr_2,
		0,
		"ganssDayCycleNumber"
		},
};
static ber_tlv_tag_t asn_DEF_GANSSReferenceTime_R10_Ext_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_GANSSReferenceTime_R10_Ext_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* ganssDayCycleNumber at 1149 */
};
static asn_SEQUENCE_specifics_t asn_SPC_GANSSReferenceTime_R10_Ext_specs_1 = {
	sizeof(struct GANSSReferenceTime_R10_Ext),
	offsetof(struct GANSSReferenceTime_R10_Ext, _asn_ctx),
	asn_MAP_GANSSReferenceTime_R10_Ext_tag2el_1,
	1,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_GANSSReferenceTime_R10_Ext = {
	"GANSSReferenceTime-R10-Ext",
	"GANSSReferenceTime-R10-Ext",
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
	asn_DEF_GANSSReferenceTime_R10_Ext_tags_1,
	sizeof(asn_DEF_GANSSReferenceTime_R10_Ext_tags_1)
		/sizeof(asn_DEF_GANSSReferenceTime_R10_Ext_tags_1[0]), /* 1 */
	asn_DEF_GANSSReferenceTime_R10_Ext_tags_1,	/* Same as above */
	sizeof(asn_DEF_GANSSReferenceTime_R10_Ext_tags_1)
		/sizeof(asn_DEF_GANSSReferenceTime_R10_Ext_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_GANSSReferenceTime_R10_Ext_1,
	1,	/* Elements count */
	&asn_SPC_GANSSReferenceTime_R10_Ext_specs_1	/* Additional specs */
};

