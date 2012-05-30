use strict;
use warnings;
use Test::More;

plan tests => 5;

use SUPL::XS;

my $supl_pkt = pack( "H*", "002b0100004c4d0e0e110e3ad7107bd299abd33a81a34c80c1a21c75ae20f7a53357a6750346991990000a" );

my $supl_pdu = SUPL::XS::decode_ulp_pdu($supl_pkt);
isa_ok($supl_pdu, "SUPL::XS::ULP_PDU_t");

my $dump_expect = <<'EOD';
ULP-PDU ::= {
                length: 43
                version: Version ::= {
                    maj: 1
                    min: 0
                    servind: 0
                }
                sessionID: SessionID ::= {
                    slpSessionID: SlpSessionID ::= {
                        sessionID: 31 34 38 38
                        slpId: supl.vodafone.com
                    }
                }
                message: SUPLINIT ::= {
                    posMethod: 3
                    sLPAddress: supl.vodafone.com
                    qoP: QoP ::= {
                        horacc: 25
                        maxLocAge: 0
                        delay: 5
                    }
                    sLPMode: 0
                }
            }
EOD
chomp( $dump_expect );
my $dump = $supl_pdu->dump();

my $xml_expect = <<'EOX';
<ULP-PDU>
    <length>43</length>
    <version>
        <maj>1</maj>
        <min>0</min>
        <servind>0</servind>
    </version>
    <sessionID>
        <slpSessionID>
            <sessionID>31 34 38 38</sessionID>
            <slpId>
                <fQDN>supl.vodafone.com</fQDN>
            </slpId>
        </slpSessionID>
    </sessionID>
    <message>
        <msSUPLINIT>
            <posMethod><agpsSETbasedpref/></posMethod>
            <sLPAddress>
                <fQDN>supl.vodafone.com</fQDN>
            </sLPAddress>
            <qoP>
                <horacc>25</horacc>
                <maxLocAge>0</maxLocAge>
                <delay>5</delay>
            </qoP>
            <sLPMode><proxy/></sLPMode>
        </msSUPLINIT>
    </message>
</ULP-PDU>
EOX
my $xml_dump = $supl_pdu->xml_dump();

my $direct_xml_dump = SUPL::XS::ulp_pdu_to_xml($supl_pkt);
my $direct_dump = SUPL::XS::dump_ulp_pdu($supl_pkt);

cmp_ok( $dump, "eq", $dump_expect, "dump" );
#use Text::Diff;
#my $diff = diff( \$direct_dump, \$dump, { STYLE => "Unified" } );
#diag $diff;

#diag( "end of \$dump: ", ord( substr( $dump, -1, 1 ) ) );
#diag( "end of \$direct_dump: ", ord( substr( $direct_dump, -1, 1 ) ) );

cmp_ok( $direct_dump, "eq", $dump, "dump vs. direct_dump" );

cmp_ok( $xml_dump, "eq", $xml_expect, "xml_dump" );
cmp_ok( $xml_dump, "eq", $direct_xml_dump, "xml_dump vs. ulp_pdu_to_xml" );
