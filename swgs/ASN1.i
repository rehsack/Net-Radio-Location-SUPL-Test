%typemap(in) OCTET_STRING_t {
    if( 0 == (SvFLAGS($input) & (SVf_OK & ~SVf_ROK)) )
	croak("Argument $argnum is not an embedded ip address.");
    OCTET_STRING_fromBuf(&$1, SvPV_nolen($input), SvLEN($input));
}

%typemap(out) OCTET_STRING_t {
    if (argvi >= items) {
	EXTEND(sp,1); /* Extend the stack by 1 object */
    }
    $result = sv_newmortal();
    sv_setpvn($result, (char *)($1.buf), $1.size);

    ++argvi; /* intentional - not portable between languages */
}

%typemap(out) OCTET_STRING_t * {
    if (argvi >= items) {
	EXTEND(sp,1); /* Extend the stack by 1 object */
    }
    $result = sv_newmortal();
    sv_setpvn($result, (char *)($1->buf), $1->size);

    ++argvi; /* intentional - not portable between languages */
}

%typemap(newfree) OCTET_STRING_t "asn_DEF_OCTET_STRING.free_struct(&asn_DEF_OCTET_STRING, &$1, 1);"
%typemap(newfree) OCTET_STRING_t * "if( $1 ) { asn_DEF_OCTET_STRING.free_struct(&asn_DEF_OCTET_STRING, $1, 0); }"

// built-in
%apply OCTET_STRING_t { BIT_STRING_t, IA5String_t, VisibleString_t };
