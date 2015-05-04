chpw - Simple Active Directory Password Change Interface
========================================================

[![Bitdeli Badge](https://d2weczhvl823v0.cloudfront.net/ofalk/chpw/trend.png)](https://bitdeli.com/free "Bitdeli Badge")

========================================================

chpw is a simple web interface for letting users change their AD (Microsoft
Active Directory) passwords in a self-service manner.

Features
--------

* Let users change their passwords from everywhere via any normal web browser
* "Change Password upon first login" is supported
* Simple CGI written in Perl
* No long chain of depencies (at least ATM)
* Easy to enhance

"Installation"
--------------

Checkout the repository somewhere and add the following snippet to your Apache
config - adjust to your needs/location:

    Alias /chpw /var/www/chpw
	<Directory /var/www/chpw>
        AllowOverride All
        Options +ExecCGI +SymlinksIfOwnerMatch
        AddHandler cgi-script .pl
        DirectoryIndex chpw.pl
    </Directory>

Create a file called chpw.yml in this directory and change the default settings
to reflect your environment:

URI: 'ldaps://dc01'
bind_dn: 'CN=ldap,cn=Users,dc=local'
bind_pw: 'mysupersecretropass'
base_dn: 'dc=local'
search_filter: '(!(userAccountControl:1.2.840.113556.1.4.803:=2))'

You might not need/want to cahnge the searchfilter, but the example does ignore
disabled users - which might be a good idea.

License
-------

GPL

Thanks
------

This script is based on a script by

    Evan Hoffmans <evanhoffman AT evanhoffman DOT com>

thanks Evan for the good basis!

Bugs / Known Problems / TODO
----------------------------

Most probably there are bugs. Feel free to fix them.
A known problem is that the errors returned by MS AD are not catched and shown
in an user-friendly way. This is on my TODO list.
Code-quality isn't very good, this was a quick-hack.
HTML quality is a shame and should be enhanced.

Author / Contact / Support
--------------------------

Feel free to contact me via mail:

    Oliver Falk <oliver AT linux DASH kernel DOT at>
