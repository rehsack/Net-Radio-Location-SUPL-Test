package SUPL::MainLoop;

use strict;
use warnings;

our $VERSION = 0.001;

use Carp qw(croak);

use Net::DBus::Reactor;

=head1 NAME

SUPL::MainLoop - Net::DBus::Reactor wrapper for SUPL Tests

=head1 DESCRIPTION

This package wraps L<Net::DBus::Reactor> for controlled D-Bus objects and
test instances. I/O handles of controlled objects are added to the watch
list of Net::DBus::Reactor on adding and remove on removing of objects.

=head1 METHODS

=cut

my $instance;

=head2 new

Instantiates new SUPL::MainLoop. Thus it's a singleton, always the same
instance is returned. The behavior in multi-threaded programs is undefined.

=cut

sub new
{
    $instance and return $instance;

    my $class = $_[0];
    my $instance = bless( { objects => [] }, $class );

    return $instance;
}

=head2 add

  SUPL::MainLoop->add($obj);

Adds a new object to be controlled.

If the added object wants to be triggered when a handle is ready for read
(C<< $obj->can("trigger_read") >>), the appropriate handle is passed to
L<Net::DBus::Reactor/METHODS|add_read> method of net::DBus::Reactor.

=cut

sub add
{
    $instance or __PACKAGE__->new();

    $_[0]->isa(__PACKAGE__) and shift; # discard OO style 1st self argument
    scalar(@_) == 1 or croak "Insufficient arguments";

    my $obj = $_[0];

    if( $obj->can("trigger_read") )
    {
	my $fh = $obj->get_read_trigger();
	my $cb = sub {
	    $obj->trigger_read();
	};
	Net::DBus::Reactor->add_read( $fh, $cb, 1 ); # add callback on $fh is readable and enable
    }

    push( @{$instance->{objects}}, $obj );

    return;
}

=head2 remove

  SUPL::MainLoop->remove($obj);

Removes an object from the list of controlled objects. 

If the added object wants to be triggered when a handle is ready for read
(C<< $obj->can("trigger_read") >>), the appropriate handle is passed to
L<Net::DBus::Reactor/METHODS|remove_read> method of net::DBus::Reactor.

When the last object is removed, the reactor is shut down.

=cut

sub remove
{
    $instance or croak "Uninitialized";

    $_[0]->isa(__PACKAGE__) and shift; # discard OO style 1st self argument
    scalar(@_) == 1 or croak "Insufficient arguments";

    my $obj = $_[0];
    my @managed = grep { $obj == $_ } @{$instance->{objects}};

    @managed or croak "Not managed";

    if( $obj->can("trigger_read") )
    {
	my $fh = $obj->get_read_trigger();
	Net::DBus::Reactor->remove_read( $fh ); # remove callback on $fh is readable
    }

    @{$instance->{objects}} = map { $_ == $obj ? () : ($_) } @{$instance->{objects}};

    scalar(@{$instance->{objects}}) == 0 and Net::DBus::Reactor->main()->shutdown();

    return;
}

=head2 run

Start's the main loop via Net::DBus::Reactor.

When SUPL::MainLoop hasn't been instantiated or no objects are controlled,
it dies with exception.

=cut

sub run
{
    $instance or croak "Uninitialized";

    $_[0]->isa(__PACKAGE__) and shift; # discard OO style 1st self argument
    scalar(@{$instance->{objects}}) or croak "Nothing managed";

    Net::DBus::Reactor->main()->run();

    # XXX explicitely destroy managed objects or let __PACKAGE__::DESTROY handle it?

    return;
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
