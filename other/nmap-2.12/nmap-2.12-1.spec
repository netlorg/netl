# This is an RPM (Redhat Package Manager) SPEC file for Fyodor's nmap.
# This file can be used with 'rpm -bb [specfile]' to create a binary
# package (user-installable RPM) for nmap, from the source TAR file.

# Contributors to this .spec file:
# Chris Wilson <cmw32@cam.ac.uk>
# Fyodor <fyodor@dhp.com>
# Oren Tirosh <oren@hishome.net> 
# Riku Meskanen <mesrik@cc.jyu.fi>
# Ian Macdonald <ian@caliban.org>

Summary: Network exploration tool and security scanner
Name: nmap
Version: 2.12
Release: 1
Copyright: GPL
Group: Networking/Utilities
Source: http://www.insecure.org/nmap/nmap-2.12.tgz
URL: http://www.insecure.org/nmap/
BuildRoot: /tmp/build-%{name}-2.12
# The BuildRoot specifies where RPM will look for the files in the %files
# secion (i.e. relative to the BuildRoot), and also sets the value of the
# $RPM_BUILD_ROOT variable. The default, '/', causes the nmap utility
# to be ACTUALLY INSTALLED on the BUILD system (the system where the RPM
# is created). It also requires 'rpm -bb [specfile]' to be run as root.
Packager: Fyodor <fyodor@dhp.com>
Vendor: Fyodor <fyodor@dhp.com>


%changelog

* Sun Jan 10 1999 Fyodor <fyodor@dhp.com>

- Merged in spec file sent in by Ian Macdonald <ianmacd@xs4all.nl>

* Tue Dec 29 1998 Fyodor <fyodor@dhp.com>

- Made some changes, and merged in another .spec file sent in
  by Oren Tirosh <oren@hishome.net>

* Mon Dec 21 1998 Riku Meskanen <mesrik@cc.jyu.fi>

- initial build for RH 5.x

%description

Nmap is a utility for network exploration or security auditing.  It supports
ping scanning (determine which hosts are up), many port scanning techniques
(determine what services the hosts are offering), and TCP/IP fingerprinting
(remote host operating system identification). Nmap also offers flexible target
and port specification, decoy scanning, determination of TCP sequence
predictability characteristics, reverse-identd scanning, and more.

%prep
%setup

%build
# CFLAGS="$RPM_OPT_FLAGS" ./configure --prefix=$RPM_BUILD_ROOT/usr/local
CFLAGS="$RPM_OPT_FLAGS" ./configure --prefix=/usr/local
make STATIC=-static
strip nmap

%install
install -d -m 755 $RPM_BUILD_ROOT/usr/local/bin
install -d -m 755 $RPM_BUILD_ROOT/usr/local/man/man1
install -d -m 755 $RPM_BUILD_ROOT/usr/local/lib/nmap
#install -m 755 $RPM_BUILD_ROOT/
make install bindir=$RPM_BUILD_ROOT/usr/local/bin mandir=$RPM_BUILD_ROOT/usr/local/man libdir=$RPM_BUILD_ROOT/usr/local/lib/nmap

# build directory and file lists
find $RPM_BUILD_ROOT -type d |
  sed -e "s#^$RPM_BUILD_ROOT#%attr(-, root, root) %dir #g" > rpm-files

find $RPM_BUILD_ROOT -type f |
  sed -e "s#^$RPM_BUILD_ROOT#%attr(-, root, root) #g" >> rpm-files

# cat <<DOCS >> rpm-files
# %attr(644, root, root) %doc INSTALL COPYING docs/*
# DOCS

%clean
rm -rf $RPM_BUILD_ROOT

%files -f rpm-files

#eof

