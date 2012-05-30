package SUPL::DBusObject::RecvPushMsg;

use strict;
use warnings;

use 5.010;

=head1 NAME

SUPL::DBusObject::RecvPushMsg - DBus Server Object to receive SUPL PushMessages

=head1 DESCRIPTION

This package provides a DBus Object with the interface to receive
notification's from oFono's mmsd about PushMessages with the WAP Application
ID C<x-oma-application:ulp.ua> and the Content Type
C<application/vnd.omaloc-supl-init>.

An appropriate mmsd configuration looks like follows:

  [SUPL]
  # simple match on the content type
  MatchContentType=application/vnd.omaloc-supl-init
  # match on WAP application id
  MatchApplicationId=x-oma-application:ulp.ua
  # D-Bus session or system bus
  TargetBus=session
  # D-Bus service name
  TargetService=org.vfnet.supl
  # D-Bus target path
  TargetPath=/org/vfnet/supl/PushConsumer

The C<TargetService> and the C<TargetPath> must passed when instantiating
this object as C<< @cfg{"bus-name", "object-path"} >>.

Currently the patch distributed below patches/mmsd/ must be applied to the
mmsd sources to allow mmsd to identify WAP Application ID's submitted as
text.

=head1 METHODS

=cut

our $VERSION = 0.001;

use base qw(SUPL::DBusObject);
use Net::DBus::Exporter qw(org.ofono.mms.PushConsumer);

use Log::Any qw($log);
use Digest::SHA qw(hmac_sha1);

use SUPL::Test;

=head2 new

Instantiates new PushMessage receiver from oFono's mmsd. The parameters
I<bus-name> and I<object-path> must be specified as described under
L</"DESCRIPTION"> in the way documented at L<SUPL::DBusObject/new|SUPL::DBusObject::new>.

=cut

sub new
{
    my ( $class, %cfg ) = @_;
    my $self = $class->SUPER::new(%cfg);

    bless( $self, $class );

    SUPL::MainLoop->add($self);

    return $self;
}

=head2 Notify

Receives notification from mmsd as described in C<mmsd/doc/consumer.txt>.

Expects two array of bytes as parameter containing the PushMessage
header and body (SUPLINIT payload).

=cut

dbus_method( "Notify", [ [ "array", "byte" ], [ "array", "byte" ] ], ["int32"] );

sub Notify
{
    my ( $self, $header, $body ) = @_;

    my $body_str = join( "", map { chr($_) } @$body );

    my $test = SUPL::Test->new();
    $test->handle_supl_pdu($body_str);

    return 0;
}

=head2 Release

Receives notification from mmsd that mmsd process ends. This notification
is ignored and might be result in a configurable exit in future.

=cut

dbus_method( "Release", [], [] );

sub Release
{
    my $self = $_[0];
    # XXX: if($self->{cfg}->{QuitOnRelease})
    # SUPL::MainLoop->remove($self);
}

=head1 AUTHOR

Jens Rehsack, C<< <rehsack at cpan.org> >>

=head1 BUGS

Please report any bugs or feature requests to
C<bug-supl-test at rt.cpan.org>, or through the web interface at
L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=SUPL-Test>.
I will be notified, and then you'll automatically be notified of progress
on your bug as I make changes.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc SUPL::Test

You can also look for information at:

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=SUPL-Test>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/SUPL-Test>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/SUPL-Test>

=item * Search CPAN

L<http://search.cpan.org/dist/SUPL-Test/>

=back

=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

Copyright 2012 Jens Rehsack.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.

=cut

1;
