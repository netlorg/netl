%define NETL_VERSION 1.10
Summary: Network monitoring tool.
Name: netl
Version: %{NETL_VERSION}
Release: 1wdl
Copyright: GPL
Group: Networking/Monitor
Source: netl-%{NETL_VERSION}.tar.gz
Buildroot: /tmp/netl-%{NETL_VERSION}-root
Url: http://www.netl.org
Obsoletes: netl
Provides: netl

%description
netl is a programmable network logger and monitor.

netl can be configured to look for particular types of TCP, UDP or ICMP
packets, or can be setup to look for generic IP packets or even raw
ethernet frames.
%prep
%setup

%build
./configure --prefix=/usr --with-perl=/usr/bin/perl
make
make test
make README

%install
make install INST=$RPM_BUILD_ROOT
make install.conf INST=$RPM_BUILD_ROOT

%clean
rm -rf $RPM_BUILD_ROOT

%files
%dir /usr/lib/netl-%{NETL_VERSION}
%config /etc/netl.conf
%doc doc/*.html
/usr/bin/*
/usr/sbin/*
/usr/man/man?/*
/usr/lib/netl
/usr/lib/netl-%{NETL_VERSION}/*

%changelog
* Mon Jul 22 2000 Graham THE Ollis <ollisg@netl.org>
- updated to version 1.10\

* Mon Dec 6 1999 Graham THE Ollis <ollisg@netl.org>
- changed the URL to the new www.netl.org

* Thu Oct 21 1999 Graham THE Ollis <ollisg@wwa.com>
- rewrote this spec by spying on the egcs.spec file which comes with redhat 6.0

