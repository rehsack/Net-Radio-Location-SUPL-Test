package SUPL::RecvPushMsg;

use strict;
use warnings;

use 5.014;

our $VERSION = 0.001;

use ULP_PDU;

use base qw(Net::DBus::Object);
use Net::DBus::Exporter qw(org.ofono.mms.PushConsumer);

use Digest::SHA qw(hmac_sha1);

use SUPL::Test;

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

    my $body_str = join( "", map { chr($_) } @$body );

    my $test = SUPL::Test->new();
    $test->handle_supl_pdu($body_str);

    return 0;
}

dbus_method("Release", [], []);
sub Release
{
    my $self = $_[0];
    SUPL::MainLoop->remove($self);
}

1;
