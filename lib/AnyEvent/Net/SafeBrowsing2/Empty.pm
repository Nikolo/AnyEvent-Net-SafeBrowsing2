package AnyEvent::Net::SafeBrowsing2::Empty;

use strict;
use warnings;
use Mouse;

=head1 NAME

AnyEvent::Net::SafeBrowsing2::Empty - Fake back-end storage for the Safe Browsing v2 database 

=head1 SYNOPSIS

  package AnyEvent::Net::SafeBrowsing2::Empty;

  use base 'AnyEvent::Net::SafeBrowsing2::Storage';

=head1 SYNOPSIS

AnyEvent::Net::SafeBrowsing2::Storage cannot be used directly. Instead, use a class inheriting AnyEvent::Net::SafeBrowsing2::Storage, like L<AnyEvent::Net::SafeBrowsing2::Empty>.


  use AnyEvent::Net::SafeBrowsing2::Empty;

  my $storage = AnyEvent::Net::SafeBrowsing2::Empty->new();
  ...
  $storage->close();

=head1 DESCRIPTION

This is an implementation of L<AnyEvent::Net::SafeBrowsing2::Storage> using Fake storage.

=cut


=head1 CONSTRUCTOR

=over 4

=back

=head2 new()

Create a AnyEvent::Net::SafeBrowsing2::Empty object

  my $storage = AnyEvent::Net::SafeBrowsing2::Empty->new({
	  connected_cb       => sub {}
  });

Arguments

=over 4

=item connected_cb

Required. Callback CodeRef

=back

=cut

sub BUILD {
	my $self = shift;
	$self->connected_cb->();
}

=head1 PUBLIC FUNCTIONS

=over 4

See L<AnyEvent::Net::SafeBrowsing2::Storage> for a complete list of public functions.

=back

=cut

sub get_regions { 
	my ($self, %args) = @_;
	$args{cb}->('','');
}

sub delete_add_chunks { 
	my ($self, %args) = @_;
	$args{cb}->();
}

sub delete_sub_chunks { 
	my ($self, %args) = @_;
	$args{cb}->();
}

sub get_add_chunks { 
	my ($self, %args) = @_;
	$args{cb}->();
} 

sub delete_full_hashes {
	my ($self, %args) = @_;
	$args{cb}->();
}

sub add_chunks_s {
	my ($self, %args) = @_;
	$args{cb}->();
}

sub add_chunks_a {
	my ($self, %args) = @_;
	$args{cb}->();
}

no Mouse;
__PACKAGE__->meta->make_immutable();

=head1 CHANGELOG

=over 4

=back

=head1 SEE ALSO

See L<AnyEvent::Net::SafeBrowsing2> for handling Safe Browsing v2.

See L<AnyEvent::Net::SafeBrowsing2::Storage> for the list of public functions.

Google Safe Browsing v2 API: L<http://code.google.com/apis/safebrowsing/developers_guide_v2.html>

=head1 AUTHOR

Nikolay Shulyakovskiy, E<lt>shulyakovskiy@mail.ruE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2014 by Nikolay Shulyakovskiy

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.


=cut

1;
