package AnyEvent::Net::SafeBrowsing2::Storage;

use strict;
use warnings;
use Mouse;

=head1 NAME

AnyEvent::Net::SafeBrowsing2::Storage - Base class for storing the Safe Browsing v2 database

=head1 SYNOPSIS

  package AnyEvent::Net::SafeBrowsing2::Tarantool;

  use base 'AnyEvent::Net::SafeBrowsing2::Storage';

=head1 DESCRIPTION

This is the base class for implementing a storage mechanism for the Safe Browsing v2 database. See L<AnyEvent::Net::SafeBrowsing2::Tarantool> for an example of implementation.

This module cannot be used on its own as it does not actually store anything. All methods should redefined. Check the code to see which arguments are used, and what should be returned.

=cut

=head1 CONSTRUCTOR

=over 4

=back

=head2 new()

  Create a AnyEvent::Net::SafeBrowsing2::Storage object

  my $storage	=> AnyEvent::Net::SafeBrowsing2::Storage->new();

Arguments

=over 4

=item master_server

Optional. Master address database server host:port

=back

=item slave_server

Optional. Slave address database server host:port

=back

=item log

Required. Class for log writing. Default AnyEvent::Net::SafeBrowsing2::Log

=cut

has master_server => ( is => 'rw', isa => 'Str' );
has slave_server  => ( is => 'rw', isa => 'Str' );
has dbh           => ( is => 'rw', isa => 'Object' );
has log_class     => ( is => 'rw', isa => 'Str', default => 'AnyEvent::Net::SafeBrowsing2::Log' );

=head1 PUBLIC FUNCTIONS

=over 4

=back

=head2 get_regions()

Return the regions of existings ids in db 

	$storage->get_regions( list => 'goog-malware-shavar', cb => sub { my($a_range, $s_range) = @_; })

Arguments 

=over 4

=item list

Required. Safe Browsing list name

=item cb

CodeRef what be called after request to db

=back

=cut

sub get_regions { die "unimplemented method called!" }

=head2 delete_add_chunks()

Delete add chunks from the local database

	$storage->delete_add_chunks(chunknums => [qw/37444 37445 37446/], list => 'goog-malware-shavar', cb => sub {});

Arguments

=over 4

=item chunknums

Required. Array of chunk numbers

=item list

Required. Safe Browsing list name

=item cb

CodeRef what be called after request to db

=back

=cut

sub delete_add_chunks { die "unimplemented method called!" }

=head2 delete_sub_chunks()

Delete sub chunks from the local database

	$storage->delete_sub_chunks(chunknums => [qw/37444 37445 37446/], list => 'goog-malware-shavar', cb => sub {});

Arguments

=over 4

=item chunknums

Required. Array of chunk numbers

=item list

Required. Safe Browsing list name

=item cb

CodeRef what be called after request to db

=back

=cut

sub delete_sub_chunks { die "unimplemented method called!" }

=head2 get_add_chunks()

Returns a list of chunks for a given host key for all lists.

	$storage->get_add_chunks(hostkey => HEX, cb => sub { my ($chunks) = @_; });

Arguments

=over 4

=item hostkey.

Required. Host key.

=item list

Required. Safe Browsing list name.

=item cb

Required. Callback that will be called after request to db

=back

Callback params 

=over 4

Array of add chunks in the same format as described above:

    (
		{ 
			chunknum	=> 25121,
			hostkey		=> hex('12345678'),
			prefix		=> '',
			list		=> 'goog-malware-shavar'
		},
		{ 
			chunknum	=> '25121',
			hostkey		=> hex('12345678'),
			prefix		=> hex('2fc96b9f'),
			list		=> 'goog-malware-shavar'
		},
	);

=back

=cut

sub get_add_chunks { die "unimplemented method called!" } 

=head2 delete_full_hashes()

Delete full hashes from the local database

	$storage->delete_full_hashes(chunknums => [qw/2154 2156 2158/], list => 'goog-malware-shavar', cb => sub {});


Arguments

=over 4

=item chunknums

Required. Array of chunk numbers.

=item list

Required. Safe Browsing list name.

=item cb

Required. Callback that will be called after request to db

=back

=cut

sub delete_full_hashes {}

=head2 add_chunks_s()

Add 'sub chunk' information to the local database

  $storage->add_chunks_s(chunknum => 2154, chunks => [{host => HEX, prefix => ''}], list => 'malware-shavar', cb => sub { my ($status) = @_});

Arguments

=over 4

=item chunknum

Required. Chunk number.

=item chunks

Required. Array of chunks

For add chunks, each element of the array is an hash reference in the following format:

  {
    host => HEX,
	prefix => HEX
  }

For sub chunks, each element of the array is an hash reference in the following format:

  {
    host => HEX,
	prefix => HEX,
    add_chunknum => INTEGER
  }

=item list

Required. Safe Browsing list name.

=item cb

Required. Callback that will be called after request to db

=back

=cut

sub add_chunks_s {die "unimplemented method called!"}

=head2 add_chunks_a()

Add 'add chunk' information to the local database

  $storage->add_chunks_a(chunknum => 2154, chunks => [{host => HEX, prefix => ''}], list => 'malware-shavar', cb => sub { my ($status) = @_});

Arguments

=over 4

=item chunknum

Required. Chunk number.

=item chunks

Required. Array of chunks

Each element of the array is an hash reference in the following format:

  {
    host => HEX,
	prefix => HEX
  }

=item list

Required. Safe Browsing list name.

=item cb

Required. Callback that will be called after request to db

=back

=cut

sub add_chunks_a {die "unimplemented method called!"}

no Mouse;
__PACKAGE__->meta->make_immutable();

=head1 SEE ALSO

See L<AnyEvent::Net::SafeBrowsing2> for handling Safe Browsing v2.

See L<AnyEvent::Net::SafeBrowsing2::Tarantool> or L<AnyEvent::Net::SafeBrowsing2::Empty> for an example of storing and managing the Safe Browsing database.

Google Safe Browsing v2 API: L<http://code.google.com/apis/safebrowsing/developers_guide_v2.html>

=head1 AUTHOR

Nikolay Shulyakovskiy, or E<lt>shulyakovskiy@mail.ruE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2014 by Nikolay Shulyakovsky

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.

=cut

1;
