%define NETL_VERSION 1.08
%define PERL_VERSION 5.00503
Summary: GUI front end to Network monitoring tool netl.
Name: tknetl
Version: %{NETL_VERSION}
Release: 1
Copyright: GPL
Group: Networking/Monitor
Source: tknetl-%{NETL_VERSION}.tar.gz
Buildroot: /tmp/tknetl-%{NETL_VERSION}-root
Url: http://www.wwa.com/~ollisg/core.html
Requires: perl = %{PERL_VERSION}
Requires: perl-Tk
Requires: netl = 1.08
Obsoletes: tknetl
Provides: tknetl

%description
tknetl is a GUI front end for netl.  netl is a customizable network
logger and monitor.

netl can be configured to look for particular types of TCP, UDP or ICMP
packets, or can be setup to look for generic IP packets or even raw
ethernet frames.

you need netl, perl5 and perl/Tk8 inorder to use tknetl

%prep
%setup

%build
/usr/bin/perl%{PERL_VERSION} Makefile.PL --config /usr/lib/netl-%{NETL_VERSION} /usr/lib/netl-%{NETL_VERSION}/include
make

%install
make install PREFIX=$RPM_BUILD_ROOT/usr

%clean
rm -rf $RPM_BUILD_ROOT

%files
/usr/*

%changelog
* Thu Oct 21 1999 Graham THE Ollis <ollisg@wwa.com>
- created spec for tknetl
