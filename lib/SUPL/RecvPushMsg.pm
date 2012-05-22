package SUPL::RecvPushMsg;

use strict;
use warnings;

use 5.014;

our $VERSION = 0.001;

use ULP_PDU;

use base qw(Net::DBus::Object);
use Net::DBus::Exporter qw(org.ofono.mms.PushConsumer);

use Digest::SHA qw(hmac_sha1);

sub new
{
    my $class = $_[0];
    my $service = $_[1] // _default_service();
    my $self = $class->SUPER::new($service, "/org/ofono/supl");

    bless( $self, $class );

    SUPL::MainLoop->add($self);

    return $self;
}

sub _default_service
{
    my $bus = Net::DBus->find();
    my $service = Net::DBus::Service->new($bus, "org.ofono.supl");

    return $service;
}

dbus_method("Notify", [["array", "byte"], ["array", "byte"]], ["int32"]);
sub Notify
{
    my $self = shift;
    my $header = shift;
    my $body = shift;

    use Data::Dumper;
    print Dumper $body;

    my $body_str = join( "", map { chr($_) } @$body );
    print Dumper $body_str;

    # init SUPL::Test and call it's recv'd()

    eval {
	my $supl_init = ULP_PDU::decode_ulp_pdu($body_str);
	print Dumper $supl_init;
	print Dumper $supl_init->{message}->{present};
	if( $supl_init->{message}->{present} == $ULP_PDU::UlpMessage_PR_msSUPLINIT )
	{
	    print "SUPLINIT.PosMethod: ", Dumper $supl_init->{message}->{choice}->{msSUPLINIT}->{posMethod};
	}
    };
    if($@) {
	print STDERR "$@\n";
    }

    return 0;
}

dbus_method("Release", [], []);
sub Release
{
    my $self = $_[0];
    SUPL::MainLoop->remove($self);
}

1;
