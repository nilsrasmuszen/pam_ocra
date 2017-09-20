pam_ocra
========

[RFC6287](http://tools.ietf.org/html/rfc6287) (OCRA) pam module


Limitations
-----------

  - intended target platform is GNU/Linux
  - Session DataInput parameter is not supported


Installation
------------

Use the Linux port security/pam_ocra

  - install berkleydb 5.3
  - install openssl (dev packages with headers)
  - install pam (dev packages with headers)
  - install autotools
  - PREFIX=/usr/local make -f Makefile.default all
    (runs autotools, configure && make)
  - make install (depending of prefix as root)
  - configure pam to use the library


Basic Use
---------

    $ ocra_tool init -f ~foobar/.ocra \
              -s OCRA-1:HOTP-SHA1-6:C-QN08-PSHA1 \
              -k 00112233445566778899aabbccddeeff00112233 \
              -c 10 -w 50 -p 1234

will create the ocra db file ".ocra" in the home directory of user "foobar";
set the OCRA suite, key, counter, counter_window and pin.

If for example /etc/pam.d/sshd has the line

    auth    required    /usr/local/lib/pam_ocra.so

and sshd is configured to use PAM, "foobar" can log in using an OCRA token.

If for example /etc/pam.d/xscreensaver has the line

    auth    required    /usr/local/lib/pam_ocra.so

and xscreensaver is configured to use PAM, "foobar" can log in using an OCRA
token.


Advanced Use
------------

    $ ocra_tool sync_counter -f ~foobar/.ocra \
              -c 12345678 -r 000000 -v 111111

will sync the counter in the ocra db file ".ocra" in the home directory of user
"foobar" to the counter in the OTP token by brute forcing for the challenge
12345678 until the response 000000 is found and the following response 111111
validates.


PAM Options
~~~~~~~~~~~

If you add arguments to the line in the PAM config, it is possible to change
the appearance of the challenge.

    cmsg=Challenge:%_%a% rmsg=Response:%_ cpad=3

Available format strings are:

 * %a: Accessible OCRA challenge (separate every cpad bytes)
 * %c: OCRA challenge
 * %u: UTC time
 * %l: Local time
 * %_: A literal space
 * %%: A literal percent sign


Two Factor Authentication
~~~~~~~~~~~~~~~~~~~~~~~~~

Use the OCRA token to secure services is done by adding the pam_ocra.so to
the associated /etc/pam.d configuration. The following examples enable 2FA for
OpenSSH and Sudo.


net-misc/openssh
++++++++++++++++

To configure the *OpenSSH* service to use the OCRA token as a second factor,
remove the pam_unix *auth* method from /etc/pam.d/sshd (or its includes) and
change the /etc/ssh/sshd_config to have the *ChallengeResponseAuthentication*
set to *Yes* and allow publickey,keyboard-interactive:pam as
*AuthenticationMethods*. The ',' means that both methods are required.

    ChallengeResponseAuthentication yes
    AuthenticationMethods publickey,keyboard-interactive:pam


app-admin/sudo
++++++++++++++

If for /etc/pam.d/sudo has the line

    auth    required    /usr/local/lib/pam_ocra.so

and "foobar" is configured in /etc/sudoers, "foobar" can sudo using an OCRA
token.


OTP usage
~~~~~~~~~

Use the OCRA token to secure systems by not setting any passwords for users but
force them to use the token to authenticate. The following examples enable OTP
for OpenSSH and Sudo


net-misc/openssh
++++++++++++++++

To configure the *OpenSSH* service to use only the OCRA token, remove the *auth*
pam_unix method from /etc/pam.d/sshd and change the /etc/ssh/sshd_config to have
the *ChallengeResponseAuthentication* set to *Yes* and disallow other
*AuthenticationMethods* than *keyboard-interactive:pam*.

    ChallengeResponseAuthentication yes
    AuthenticationMethods keyboard-interactive:pam


app-admin/sudo
++++++++++++++

To configure a server with sudo and no dedicated passwords, for the users,
remove the pam_unix auth method from /etc/pam.d/sudo.


Untested Services
~~~~~~~~~~~~~~~~~

PAM can be used for authentication for many services. Sometimes the service
needs some activation to use PAM (like OpenSSH) or to build special modules
(like nginx).

The process is then similar to the above described examples.

Always make sure that

* You can login the configured user with a correct OCRA Challenge/Response
* You cannot login the configured user with a bad/no Response

Should you deploy ocra_pam with one of the following services, please add
the appropriate configuration as a pull request.


Database Services
+++++++++++++++++

Avoid knowledge of a password for administration of services.
Single Factor

    dev-db/mariadb
    dev-db/percona-server
    dev-db/postgresql


Communication Services
++++++++++++++++++++++

Add second factor for services.

    net-im/jabberd2
    net-mail/cyrus-imapd
    net-mail/dovecot
    net-proxy/dante
    net-proxy/squid
    net-vpn/openvpn
    www-apache/pwauth
    www-servers/cherokee
    www-servers/nginx
    www-servers/uwsgi


Remote Login Services
+++++++++++++++++++++

Add second factor for services.

    net-misc/dropbear
    -net-misc/openssh-
    net-misc/tigervnc


File Services
+++++++++++++

    net-fs/samba
    net-ftp/ftpbase
    net-ftp/lftp
    net-ftp/proftpd
    net-ftp/pure-ftpd
    net-ftp/vsftpd


Login Services
++++++++++++++

    app-admin/sudo
    lxde-base/lxdm
    gnome-base/gdm
    x11-apps/xdm
    x11-misc/cdm
    x11-misc/i3lock
    x11-misc/lightdm
    x11-misc/slim
    x11-misc/wdm


Terminal Lock Services
++++++++++++++++++++++

    gnome-extra/cinnamon-screensaver
    kde-plasma/kscreenlocker
    mate-extra/mate-screensaver
    x11-misc/alock
    x11-misc/xlockmore
    x11-misc/xscreensaver


Desktop Keyring Services
++++++++++++++++++++++++

    gnome-base/gnome-keyring
    kde-plasma/kwallet-pam


Changelog
---------

- 1.4:

  * port code to linux (fork, not compatible with FreeBSD)

  * introduce db_storage for general access to the configuration

  * enclose in autotools

  * padding options for the prompt

- 1.3:

  * fix pam_ocra "dir=" option

  * introduce pam_ocra "rmsg=", "cmsg=" and "nodata=" options

  contributed by Richard Nichols <rdn757@gmail.com>

- 1.2:

  * Constify two local variables to avoid -Wcast-qual warnings:
    https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=198113

- 1.1:

  * change ocra_tool(8) command line interface:
    - 'help' command removed
    - 'init' -P pinhash option added
    - 'init' -c option now also accepts hex counters
    - 'info' output format changed

  * fix ocra_tool counter input:
    the -c counter option did not work for the whole value range of the counter
    paramter.

  * fix gcc builds:
    which where broken due to (cast-qual, format, sign-compare, ...) warnings.

  * fix timstamp_offset verification:
    broken termination condition in timstamp_offset verify loop did not
    account for timstamp_offset==0. The result was that verification would
    suceed for any timestamp.

  * fix counter_window and timstamp_offset verification:
    broken termination condition in counter_window verify loop did not
    account for counter_window==0. The result was that the verification
    would execute MAX_INT times before failing.

  * fix i368 builds:
    incorrect sign-compare and 64bit specific format string triggerd warnings
    which broke the build for i368 targets.

- 1.0: first release
