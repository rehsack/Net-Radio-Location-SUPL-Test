%module ULP_PDU

%include "carrays.i"

%{
/* SUPL PDU */
#include "asn1/ULP-PDU.h"
%}

%include "asn1/SUPLAUTHREQ.h"
%include "asn1/SUPLAUTHRESP.h"
%include "asn1/SUPLEND.h"
%include "asn1/SUPLINIT.h"
%include "asn1/SUPLPOS.h"
%include "asn1/SUPLPOSINIT.h"
%include "asn1/SUPLRESPONSE.h"
%include "asn1/SUPLSTART.h"
%include "asn1/ULP-PDU.h"
%include "asn1/UlpMessage.h"

%{
typedef struct _MsgBuffer
{
	uint8_t *buf;
	ssize_t size;
} MsgBuffer;

struct per_target_buffer
{
	uint8_t *buf;
	size_t pos;
	size_t size;
};

static int
per_output(const void *data, size_t size, void *op_key)
{
	struct per_target_buffer *pb = op_key;
	if (pb->size < (pb->pos + size)) {
		uint8_t *tmp = realloc(pb->buf, pb->size + 4096);
		if (!tmp) {
			/* XXX report error */
			abort();
		}
		pb->buf = tmp;
		pb->size += 4096;
	}
	memcpy( pb->buf + pb->pos, data, size );
	pb->pos += size;

	return 0;
}

static const char *
asn_dec_rval_code_str(enum asn_dec_rval_code_e code)
{
    switch(code)
    {
    case RC_OK:
	return "RC_OK - Decoded successfully";

    case RC_WMORE:
	return "RC_WMORE - More data expected, call again";

    case RC_FAIL:
	return "RC_FAIL - Failure to decode data";

    default:
	return "Unknown decoder error code";
    }
}

static MsgBuffer
encode_ulp_pdu(struct ULP_PDU *pdu)
{
	/* asn_per_data_t per_data; */
	struct per_target_buffer per_buf;
	asn_enc_rval_t rval;
	MsgBuffer retbuf = { NULL, -1 };

	if (NULL == pdu)
		return retbuf;

	per_buf.buf = calloc( 4096, sizeof(uint8_t) );
	per_buf.pos = 0;
	per_buf.size = 4096;
	rval = uper_encode( &asn_DEF_ULP_PDU, pdu, &per_output, &per_buf);

	if (rval.encoded == -1) {
		free(per_buf.buf);
		croak("error encoding ULP pdu %s: %s",
			rval.failed_type->name,
			strerror(errno));

		return retbuf; /* unreached */
	}

	if (0 == pdu->length) {
		pdu->length = per_buf.pos;
		per_buf.pos = 0;

		/* encode 2nd with length set */
		rval = uper_encode( &asn_DEF_ULP_PDU, pdu, &per_output, &per_buf);
	}

#if 0
	xer_fprint(stdout, &asn_DEF_ULP_PDU, pdu);
	fflush(stdout);
#endif

	if (rval.encoded == -1) {
		free(per_buf.buf);
		croak("error encoding ULP pdu %s: %s",
			rval.failed_type->name,
			strerror(errno));

		return retbuf; /* unreached */
	}

	retbuf.buf = per_buf.buf;
	retbuf.size = per_buf.size;

	return retbuf;
}

static struct ULP_PDU *
decode_ulp_pdu(MsgBuffer buf)
{
	struct ULP_PDU *ulp_pdu = NULL;
	asn_dec_rval_t rval;
	asn_per_data_t per_data = { buf.buf, 0, ((size_t)buf.size) * 8 };

	rval = asn_DEF_ULP_PDU.uper_decoder( 0, &asn_DEF_ULP_PDU,
					NULL, (void **)&ulp_pdu,
					&per_data);
	if (rval.code != RC_OK) {
		/* Free partially decoded ulp-pdu */
		asn_DEF_ULP_PDU.free_struct(
			&asn_DEF_ULP_PDU, ulp_pdu, 0);

		croak("error parsing ULP pdu on byte %u with %s",
			(unsigned)rval.consumed,
			asn_dec_rval_code_str(rval.code));

		return NULL; /* unreached */
	}

#if 0
	xer_fprint(stdout, &asn_DEF_ULP_PDU, ulp_pdu);
#endif

	return ulp_pdu;
}

static MsgBuffer
ulp_pdu_to_xml(MsgBuffer buf)
{
	MsgBuffer retbuf = { NULL, -1 };
	asn_enc_rval_t rval;
	struct per_target_buffer per_buf;
	struct ULP_PDU *tmp_pdu = decode_ulp_pdu(buf);

	if (NULL == tmp_pdu)
		return retbuf;

	per_buf.buf = calloc( 4096, sizeof(uint8_t) );
	per_buf.pos = 0;
	per_buf.size = 4096;
	rval = xer_encode( &asn_DEF_ULP_PDU, tmp_pdu, XER_F_BASIC, &per_output, &per_buf);

	asn_DEF_ULP_PDU.free_struct(&asn_DEF_ULP_PDU, tmp_pdu, 0);

	if (rval.encoded == -1) {
		free(per_buf.buf);
		croak("error encoding ULP pdu %s: %s",
			rval.failed_type->name,
			strerror(errno));

		return retbuf; /* unreached */
	}

	retbuf.buf = per_buf.buf;
	retbuf.size = per_buf.size;

	return retbuf;
}
%}

%extend ULP_PDU {
    ULP_PDU()
    {
	ULP_PDU_t *newobj;
	newobj = calloc( 1, sizeof(*newobj) );
	/* XXX croak on NULL */
	newobj->version.maj = 1;
	newobj->version.min = 0;
	newobj->version.servind = 0;
	return newobj;
    }

    ~ULP_PDU() {
	asn_DEF_ULP_PDU.free_struct(&asn_DEF_ULP_PDU, $self, 0);
    }

    void set_version(int maj, int min, int servind) {
	if( maj == 1 && min == 0 && servind == 0 ) {
	    self->version.maj = maj;
	    self->version.min = min;
	    self->version.servind = servind;
	}
	else {
	    croak( "Unsupported SUPL version" );
	}
    }

    void setSetSessionId_to_imsi(int sessionId, char *imsi) {
	if( NULL != $self->sessionID.setSessionID ) {
	    asn_DEF_ULP_PDU.free_struct(&asn_DEF_SetSessionID, $self->sessionID.setSessionID, 0);
	    $self->sessionID.setSessionID = NULL;
	}
	$self->sessionID.setSessionID = calloc(1, sizeof(*($self->sessionID.setSessionID)));
	$self->sessionID.setSessionID->setId.present = SETId_PR_imsi;
	BCD_OCTET_STRING_fromString(&$self->sessionID.setSessionID->setId.choice.imsi, imsi);
    }

    void setSetSessionId_to_msisdn(int sessionId, char *msisdn) {
	if( NULL != $self->sessionID.setSessionID ) {
	    asn_DEF_ULP_PDU.free_struct(&asn_DEF_SetSessionID, $self->sessionID.setSessionID, 0);
	    $self->sessionID.setSessionID = NULL;
	}
	$self->sessionID.setSessionID = calloc(1, sizeof(*($self->sessionID.setSessionID)));
	$self->sessionID.setSessionID->setId.present = SETId_PR_msisdn;
	BCD_OCTET_STRING_fromString(&$self->sessionID.setSessionID->setId.choice.msisdn, msisdn);
    }

    void copy_SlpSessionId(ULP_PDU_t *src_pdu) {
	struct SlpSessionID *src, *dst;
	OCTET_STRING_t *srcaddr;
	OCTET_STRING_t *dstaddr;

	src = src_pdu->sessionID.slpSessionID;

	if( NULL == src )
	    return; /* nothing to do */

	if( NULL != $self->sessionID.slpSessionID ) {
	    asn_DEF_ULP_PDU.free_struct(&asn_DEF_SlpSessionID, $self->sessionID.slpSessionID, 0);
	    $self->sessionID.slpSessionID = NULL;
	}

	$self->sessionID.slpSessionID = calloc(1, sizeof(*($self->sessionID.slpSessionID)));
	dst = $self->sessionID.slpSessionID;

	OCTET_STRING_fromBuf(&dst->sessionID, src->sessionID.buf, src->sessionID.size);
	switch (src->slpId.present)
	{
	case SLPAddress_PR_iPAddress:
	    dst->slpId.present = SLPAddress_PR_iPAddress;
	    switch (src->slpId.choice.iPAddress.present)
	    {
	    case IPAddress_PR_ipv4Address:
		dst->slpId.choice.iPAddress.present = IPAddress_PR_ipv4Address;
		srcaddr = &src->slpId.choice.iPAddress.choice.ipv4Address;
		dstaddr = &dst->slpId.choice.iPAddress.choice.ipv4Address;

		break;

	    case IPAddress_PR_ipv6Address:
		dst->slpId.choice.iPAddress.present = IPAddress_PR_ipv6Address;
		srcaddr = &src->slpId.choice.iPAddress.choice.ipv6Address;
		dstaddr = &dst->slpId.choice.iPAddress.choice.ipv6Address;

		break;

	    default:
		dst->slpId.choice.iPAddress.present = IPAddress_PR_NOTHING;
		croak("Invalid: source has slpSessionId but neither IP-Address nor FQDN content");

		break;
	    }

	    break;

	case SLPAddress_PR_fQDN:
	    dst->slpId.present = SLPAddress_PR_fQDN;
	    srcaddr = &src->slpId.choice.fQDN;
	    dstaddr = &dst->slpId.choice.fQDN;

	    break;

	default:
	    /* error */
	    dst->slpId.present = SLPAddress_PR_NOTHING;
	    croak("Invalid: source has slpSessionId but neither IP-Address nor FQDN content");

	    break;
	}
	OCTET_STRING_fromBuf(dstaddr, srcaddr->buf, srcaddr->size);
    }
};

%typemap(in) MsgBuffer {
    // $1 = AV2MsgBuf($input);
    // MsgBuffer retval = { NULL, -1 };
    if($input == NULL) {
	SWIG_exception_fail(SWIG_ArgError(SWIG_TypeError), "in method '" "$symname" "', argument " "$1_name" " of type '" "MsgBuffer""'");
    }
    if( SvFLAGS($input) & (SVf_OK & ~SVf_ROK) ) {
	$1.buf = SvPV($input, $1.size);
    }
    else {
	SWIG_exception_fail(SWIG_ArgError(SWIG_TypeError), "in method '" "$symname" "', argument " "$1_name" " of type '" "MsgBuffer""'");
    }
}

%typemap(newfree) MsgBuffer "do { if( $1.buf ) free($1.buf); } while(0);"
%typemap(newfree) MsgBuffer * "do { if( $1 ) { if( $1->buf ) { free( $1->buf ); } free( $1 ); } } while(0);"

%typemap(newfree) ULP_PDU_t * "asn_DEF_ULP_PDU.free_struct(&asn_DEF_ULP_PDU, $1, 0);"

%typemap(out) MsgBuffer {
    if (argvi >= items) {            
	EXTEND(sp,1); /* Extend the stack by 1 object */
    }
    $result = sv_2mortal(newSVpv($1.buf, $1.size));
    ++argvi; /* intentional - not portable between languages */
}

%newobject encode_ulp_pdu;
%newobject ulp_pdu_to_xml;

MsgBuffer encode_ulp_pdu(struct ULP_PDU *pdu);
struct ULP_PDU *decode_ulp_pdu(MsgBuffer buf);
MsgBuffer ulp_pdu_to_xml(MsgBuffer buf);
