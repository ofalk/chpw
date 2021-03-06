#!/usr/bin/perl
#
# Oliver Falk <oliver@linux-kernel.at>, 2011 - 2013
# Based on Evan Hoffmans (evanhoffman@evanhoffman.com)
# script from 13 January, 2010
#
# Base functionality from: http://search.cpan.org/~gbarr/perl-ldap/lib/Net/LDAP/FAQ.pod#..._in_MS_Active_Directory_?

use strict;
use warnings;

print "Content-Type: text/html\n\n";

use Net::LDAP;
use Unicode::Map8;
use Unicode::String qw(utf16);
use MIME::Base64;
use CGI::Lite;
use YAML::Tiny;

use constant PWCH_NEXT_LOGON => 0;
use constant NOPWCH_NEXT_LOGON => -1;
use constant ATTRS => ['dn','cn','mail', 'pwdLastSet'];

my $conf = YAML::Tiny->read('chpw.yml');

my $host = $conf->[0]->{URI} || 'ldaps://dc01';
my $bind_dn = $conf->[0]->{bind_dn} || 'CN=ldap';
my $bind_pw = $conf->[0]->{bind_pw} || 'ldapRO';
my $base_dn = $conf->[0]->{base_dn} || 'dc=local';
my $search_filter = $conf->[0]->{search_filter} || '(!(userAccountControl:1.2.840.113556.1.4.803:=2))';
my $mesg;

my $password_policy = $conf->[0]->{password_policy} || qq{
<br/>
Password policy:
<ul>
<li>Not contain the user's account name or parts of the user's full name<br/>
that exceed two consecutive characters</li>
<li>Be at least six characters in length</li>
<li>Contain characters from three of the following four categories:</li>
<li>English uppercase characters (A through Z)</li>
<li>English lowercase characters (a through z)</li>
<li>Base 10 digits (0 through 9)</li>
<li>Non-alphabetic characters (for example, !, $, #, %)</li>
</ul>
};

package ADAuth;
use constant PWCH_NEXT_LOGON => 0;
use constant NOPWCH_NEXT_LOGON => -1;
use constant ATTRS => ['dn','cn','mail', 'pwdLastSet'];

sub mod_user_pwdlastset($$) {
	my $self = shift;
	my $user_dn = shift;
	# By default we do set the flag!
	my $flag = shift || PWCH_NEXT_LOGON;

	my $ldap = Net::LDAP->new($host) or die "$@";
	my $mesg = $ldap->bind($bind_dn, password => $bind_pw );
	$mesg->is_error && die ('Bind error: '. $mesg->error);

	$mesg = $ldap->modify($user_dn,
		replace => { pwdLastSet => $flag } );

	$mesg->is_error && die ('pwdLastSet replace error: '. $mesg->error);
	$ldap->unbind();
}

sub get_user($) {
	my $self = shift;
	my $user = shift;

	my $ldap = Net::LDAP->new($host)  or  die "$@";
	my $mesg = $ldap->bind($bind_dn, password => $bind_pw );
	$mesg->is_error && die ('Bind error: '. $mesg->error);

	$mesg = $ldap->search(
			base => $base_dn,
			scope => 'sub',
			attrs => ATTRS,
			filter => "(&(samaccountname=$user)$search_filter)"
			);
	$mesg->is_error && die ('Search failed: '. $mesg->error);
	$mesg->count || die ("Search for user '$user' returned no results.");
	my $entry = $mesg->entry(0);
	$ldap->unbind();

	return $entry;
}

sub lookup_dn($) {
	my $self = shift;
	my $user = shift;

	return $self->get_user($user)->dn;
}

sub auth_user {
	my $self = shift;
	my $user_dn = shift;
	my $pass_pw = shift;

	my $entry = ADAuth->get_user($ENV{REMOTE_USER});

	# Now workaround the problem, that an account cannot login
	# via LDAP if the account has set the flag, that it must
	# change it's password upon next login
	if($entry->get_value('pwdLastSet') == PWCH_NEXT_LOGON) {
		ADAuth->mod_user_pwdlastset($user_dn, NOPWCH_NEXT_LOGON);
	}

	my $ldap = Net::LDAP->new($host)  or  die "$@";
	my $mesg = $ldap->bind($user_dn, password => $pass_pw);
	if ($mesg->is_error) {
		my $err = "Error attempting to bind as $user_dn: ". $mesg->error;
		print "<pre>$err</pre>";
		# FALSE User authentication didn't work - eg. Wrong password, user disabled or user must change password upon next logon...
		return $err;
	}
	# IMPORTANT!!! We need to reset this here!
	ADAuth->mod_user_pwdlastset($user_dn, PWCH_NEXT_LOGON);
	# TRUE. User authenticated
	return 0;
}

package main;

# build the conversion map from your local character set to Unicode
my $charmap = Unicode::Map8->new('latin1') or die;

print <<EOF;
<!doctype html>
<html lang="en">
<head>
    <title>Active Directory Password Changer</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.1.1/css/bootstrap.min.css" integrity="sha384-WskhaSGFgHYWDcbwN70/dfYBj47jz9qbsMId/iRN3ewGhXQFZCSftd1LZCfmhktB" crossorigin="anonymous">
    <link rel="stylesheet" href="chpw.css" type="text/css" media="screen" />
</head>
<body>
EOF

unless ( $ENV{'HTTPS'} eq 'on' ) {
	print "<b>This script requires HTTPS.</b>\n";
	die;

}

## TODO print "Logged in as <b>$ENV{REMOTE_USER}</b>.  LDAP URI is <b>$host</b>.<br>\n";

my $cgi = new CGI::Lite;

my %form = $cgi->parse_form_data;
$ENV{'REMOTE_USER'} = $form{'username'};
$form{'op'} = '' unless $form{'op'};

if ($form{'op'} eq 'submit') {
	my $user_dn = $form{'dn'};
	my $user_pw = $form{'oldpassword'};
	my $newpw1 = $form{'newpw1'};
	my $newpw2 = $form{'newpw2'};

	unless ( $newpw1 eq $newpw2 ) {
		print 'Password mismatch.'  unless ( $newpw1 eq $newpw2 );
		return;
	}
	unless($user_dn) {
		print 'No DN specified.';
		return;
	}

        print "<div style='margin-left: 5px'>\n";
	print "Attempting to bind as <b>$user_dn</b> ... ";

	my $err = ADAuth->auth_user($user_dn, $user_pw);
	die "Bind error (x): $err" if $err;

	print " OK.<br>\n";

	my $oldUniPW = $charmap->tou('"'.$user_pw.'"')->byteswap()->utf16();
	my $newUniPW = $charmap->tou('"'.$newpw1.'"')->byteswap()->utf16();

	print "Attempting to modify password for <b>$user_dn</b> ... ";

	my $ldap = Net::LDAP->new($host)  or  die "$@";
	my $mesg = $ldap->bind($bind_dn, password => $bind_pw );
	$mesg->is_error && die ('Bind error: '. $mesg->error);
	$mesg = $ldap->modify($user_dn,
			changes => [
			delete => [ unicodePwd => $oldUniPW ],
			add    => [ unicodePwd => $newUniPW ] ]);

	print "OK<br>\n";
        print "</div>";

#	$mesg->is_error && die ('Modify error: '. $mesg->error);
	if ($mesg->is_error) {
		my $err = '<b>Modify error</b>: '. $mesg->error;
		print "<div class='alert alert-danger' style='margin-left: 5px; font-size: 1.3em; width: 80%;' role='alert'>\n";
		print "<pre>$err</pre>\n";
		print "</div\n";
		die $err;
	}

	$ldap->unbind();
	print "<div class='alert alert-success' role='alert'>\n";
	print "VICTORY!! Successfully changed password for user $ENV{REMOTE_USER}, DN <b>$user_dn</b>, msg ID: ".$mesg->mesg_id ."\n";
	print "</div>\n";
	warn "Change password for $ENV{REMOTE_USER}";

} else {
	if (!($form{'op'} eq 'login') or !($form{'username'}) or !($form{'password'})) {
		print "<p>&nbsp;</p>\n";
		print "<form action='$ENV{REQUEST_URI}' METHOD='POST'>\n";
		print "<input type='hidden' name='op' value='login'>\n";
		print "<div class='form-group'>\n";
		print "<label for='username'>Username:</label>\n";
		print "<input type='text' name='username' placeholder='Username...' id='username' class='myinput' size='30'/><br/>\n";
		print "</div>\n";
		print "<div class='form-group'>\n";
		print "<label for='password'>Password:</label>\n";
		print "<input type='password' name='password' placeholder='Password...' id='password' class='myinput' size='30'/><br/>\n";
		print "</div>\n";
		print "<div class='form-group'>\n";
		print "<label> </label>";
		print "<button type='submit' class='btn btn-primary' name='submit'>Login</button>\n";
		print "<button type='reset'  class='btn btn-primary'              >Reset</button>\n";
		print "</div>\n";
		print "</form>\n";
	} else {
		# bind as dummy to lookup the user's DN
		my $ldap = Net::LDAP->new($host)  or  die "$@";
		my $mesg = $ldap->bind($bind_dn, password => $bind_pw );
		$mesg->is_error && die ('Bind error: '. $mesg->error);

		my $user_dn =  ADAuth->lookup_dn($ENV{REMOTE_USER});

		my $err = ADAuth->auth_user($user_dn, $form{'password'});
		die "Authentication error: $err" if $err;

                print "<div style='margin-top:5px; margin-left:5px;'>";
		print "<div style='margin-right:20px; float:right;'><a href='$ENV{REQUEST_URI}'>Return to login</a></div>\n";
		print "<div align='left' style='float:auto;'>\n";
		print "<form action='$ENV{REQUEST_URI}' METHOD='POST'>\n";
		# print "\n<!-- LDAP DN for user '$ENV{REMOTE_USER}': <b>$user_dn</b> -->\n";
		print "<input type='hidden' name='op' value='submit'/>\n";
		print "<input type='hidden' name='dn' value='$user_dn'/>\n";
		print "<input type='hidden' name='username' value='$ENV{REMOTE_USER}'/>\n";

		print "<div class='form-group'>\n";
		print "<label for='password'>Current password for <b>$ENV{REMOTE_USER}</b> <i>for confirmation</i>:</label>\n";
		print "<input class='myinput' id='password' type='password' name='oldpassword' size='30'/><br/>\n";
		print "</div>\n";

		print "<label for='newpw1'>New password for <b>$ENV{REMOTE_USER}</b>:</label>\n";
		print "<input class='myinput' id='newpw1' type='password' name='newpw1' size='30'/><br/>\n";

		print "<label for='newpw2'>New password for <b>$ENV{REMOTE_USER}</b> <i>again</i>:</label>\n";
		print "<input class='myinput' type='password' name='newpw2' size='30'/><br/>\n";

		print "<div class='form-group'>\n";
		print "<label> </label>";
		print "<button type='submit' class='btn btn-primary' name='submit'>Change password</button>\n";
		print "<button type='reset'  class='btn btn-primary'              >Reset</button>\n";
		print "</div>\n";

		print "</form>\n";
		print "</div>\n";

		print "<div>";
		print $password_policy . "\n";
		print "</div>\n";
		print "</div>\n";
	}
}

print <<EOJS;
<script src="https://code.jquery.com/jquery-3.3.1.slim.min.js" integrity="sha384-q8i/X+965DzO0rT7abK41JStQIAqVgRVzpbzo5smXKp4YfRvH+8abtTE1Pi6jizo" crossorigin="anonymous"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.3/umd/popper.min.js" integrity="sha384-ZMP7rVo3mIykV+2+9J3UJ46jBk0WLaUAdn689aCwoqbBJiSnjAK/l8WvCWPIPm49" crossorigin="anonymous"></script>
<script src="https://stackpath.bootstrapcdn.com/bootstrap/4.1.1/js/bootstrap.min.js" integrity="sha384-smHYKdLADwkXOn1EmN1qk/HfnUcbVRZyYmZ4qpPea6sjB/pTJ0euyQp0Mk8ck+5T" crossorigin="anonymous"></script>
EOJS
print '</body></html>';
