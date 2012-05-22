package SUPL::DBusObject::RecvPushMsg;

use strict;
use warnings;

use 5.014;

our $VERSION = 0.001;

use base qw(Net::DBus::Object);
use Net::DBus::Exporter qw(org.ofono.mms.PushConsumer);

use Digest::SHA qw(hmac_sha1);

use SUPL::Test;

sub new
{
    my ($class, %cfg) = @_;
    my $self = $class->SUPER::new(%cfg);

    bless( $self, $class );

    SUPL::MainLoop->add($self);

    return $self;
}

dbus_method("Notify", [["array", "byte"], ["array", "byte"]], ["int32"]);
sub Notify
{
    my ($self, $header, $body) = @_;

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
