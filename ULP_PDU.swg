%module ULP_PDU

%include "carrays.i"

%{
/* SUPL PDU */
#include "asn1/ULP-PDU.h"
%}

typedef struct ULP_PDU {
	long	 length;
	Version_t	 version;
	SessionID_t	 sessionID;
	UlpMessage_t	 message;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ULP_PDU_t;

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

static int per_output(const void *data, size_t size, void *op_key)
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

MsgBuffer
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
		croak("error encoding ULP pdu: (insert asn1c error here)");

		return retbuf;
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
		croak("error encoding ULP pdu: (insert asn1c error here)");

		return retbuf;
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
	asn_per_data_t per_data;

	{
	    ssize_t i;
	    printf("$VAR1 = [\n");
	    for( i = 0; i < buf.size; ++i )
		printf("          %u\n", buf.buf[i]);
	    printf("        ];\n");
	}

	per_data.buffer = buf.buf;
	per_data.nboff = 0;
	per_data.nbits = ((size_t)buf.size) * 8;
	rval = asn_DEF_ULP_PDU.uper_decoder( 0, &asn_DEF_ULP_PDU,
					NULL, (void **)&ulp_pdu,
					&per_data);
	if (rval.code != RC_OK) {
		croak("error parsing ULP pdu: (insert asn1c error here)");

		/* Free partially decoded ulp-pdu */
		asn_DEF_ULP_PDU.free_struct(
			&asn_DEF_ULP_PDU, ulp_pdu, 0);
		return;
	}

	xer_fprint(stdout, &asn_DEF_ULP_PDU, ulp_pdu);

	return ulp_pdu;
}
%}

%typemap(in) MsgBuffer {
    // $1 = AV2MsgBuf($input);
    // MsgBuffer retval = { NULL, -1 };
    if($input == NULL) {
	SWIG_exception_fail(SWIG_ArgError(SWIG_TypeError), "in method '" "$symname" "', argument " "$1_name" " of type '" "MsgBuffer""'");
    }
    if( SvROK($input) && ( SVt_PVAV == SvTYPE(SvRV($input) ) ) ) {
	ssize_t i;
	AV *av = (AV *)(SvRV($input));

	$1.size = av_len(av);
	if($1.size < 0) {
	    SWIG_exception_fail(SWIG_ArgError(SWIG_OverflowError), "in method '" "$symname" "', argument " "$1_name" " of type '" "MsgBuffer""' is empty");
	}
	++$1.size;
	$1.buf = malloc($1.size); /* XXX prove non-NULL return */
	for( i = 0; i < $1.size; ++i ) {
	    SV **val = av_fetch(av, i, 0 );
	    if( val && *val && (SvTYPE(*val) == SVt_IV ) ) {
		IV intval = SvIV(*val);
		if( intval > UINT8_MAX ) {
		    SWIG_exception_fail(SWIG_ArgError(SWIG_OverflowError), "in method '" "$symname" "', argument " "$1_name" " of type '" "MsgBuffer""' exceeds range");
		}
		$1.buf[i] = intval;
	    }
	    else {
		free($1.buf);
		SWIG_exception_fail(SWIG_ArgError(SWIG_TypeError), "in method '" "$symname" "', argument " "$1_name" " of type '" "MsgBuffer""' contains invalid elements");
	    }
	}
    }
    else if( SvFLAGS($input) & (SVf_OK & ~SVf_ROK) ) {
	char *svbuf = SvPV($input, $1.size);
	$1.buf = malloc($1.size); /* XXX prove non-NULL return */
	memcpy($1.buf, svbuf, $1.size);
    }
    else {
	SWIG_exception_fail(SWIG_ArgError(SWIG_TypeError), "in method '" "$symname" "', argument " "$1_name" " of type '" "MsgBuffer""'");
    }
}

%typemap(out) MsgBuffer {
#if 0
void      sv_setpvn(SV *, char *val, STRLEN len);
SV       *newSVpv(char *value, STRLEN len);
#endif
    $result = newSVpv($1.buf, $1.size);
    free($1.buf);
}

MsgBuffer encode_ulp_pdu(struct ULP_PDU *pdu);
struct ULP_PDU *decode_ulp_pdu(MsgBuffer buf);
