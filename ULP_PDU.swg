%module ULP_PDU

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

struct _MsgBuffer
{
	uint8_t *buf;
	ssize_t size;
};

%{
struct _MsgBuffer
{
	uint8_t *buf;
	ssize_t size;
};

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

struct _MsgBuffer *encode_ulp_pdu(struct ULP_PDU *pdu, struct _MsgBuffer *msgbuf)
{
	/* asn_per_data_t per_data; */
	struct per_target_buffer per_buf;
	asn_enc_rval_t rval;

	if (NULL == pdu || NULL == msgbuf)
		return NULL;

	per_buf.buf = calloc( 4096, sizeof(uint8_t) );
	per_buf.pos = 0;
	per_buf.size = 4096;
	rval = uper_encode( &asn_DEF_ULP_PDU, pdu, &per_output, &per_buf);

	if (rval.encoded == -1) {
		mms_error("error encoding ULP pdu: (insert asn1c error here)");

		free(per_buf.buf);
		return NULL;
	}

	if (0 == pdu->length) {
		pdu->length = per_buf.pos;
		per_buf.pos = 0;

		/* encode 2nd with length set */
		rval = uper_encode( &asn_DEF_ULP_PDU, pdu, &per_output, &per_buf);
	}
	xer_fprint(stdout, &asn_DEF_ULP_PDU, pdu);
	fflush(stdout);

	if (rval.encoded == -1) {
		mms_error("error encoding ULP pdu: (insert asn1c error here)");

		free(per_buf.buf);
		return NULL;
	}

	msgbuf->buf = per_buf.buf;
	msgbuf->size = per_buf.size;

	return msgbuf;
}

struct ULP_PDU *decode_ulp_pdu(uint8_t *msg, ssize_t msglen)
{
	struct ULP_PDU *ulp_pdu = NULL;
	asn_dec_rval_t rval;
	asn_per_data_t per_data;

	per_data.buffer = msg;
	per_data.nboff = 0;
	per_data.nbits = ((size_t)msglen) * 8;
	rval = asn_DEF_ULP_PDU.uper_decoder( 0, &asn_DEF_ULP_PDU,
					NULL, (void **)&ulp_pdu,
					&per_data);
	if (rval.code != RC_OK) {
		mms_error("error parsing ULP pdu: (insert asn1c error here)");

		/* Free partially decoded ulp-pdu */
		asn_DEF_ULP_PDU.free_struct(
			&asn_DEF_ULP_PDU, ulp_pdu, 0);
		return;
	}

	xer_fprint(stdout, &asn_DEF_ULP_PDU, ulp_pdu);

	return ulp_pdu;
}
%}

struct _MsgBuffer *encode_ulp_pdu(struct ULP_PDU *pdu, struct _MsgBuffer *msgbuf);
struct ULP_PDU *decode_ulp_pdu(uint8_t *msg, ssize_t msglen);
