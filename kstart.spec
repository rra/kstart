Name: kstart
Summary: Kerberos kinit variants supporting ticket refreshing
Version: 3.0
Release: 1
License: MIT, BSD
Group: System Environment/Base
URL: http://www.eyrie.org/~eagle/software/kstart/
Source: http://archives.eyrie.org/software/kerberos/%{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
BuildRequires: krb5-devel
Requires: krb5-workstation

%description
Kerberos kinit variant supporting ticket refreshing.  k5start (for
Kerberos v5) and k4start (for Kerberos v4) can be used instead of kinit to
obtain Kerberos tickets.  krenew can renew an existing ticket cache.  They
are intended primarily for use with automated processes and support some
additional features useful for that purpose, such as running as a daemon
and refreshing the ticket periodically, checking to see if an existing
ticket has expired, or obtaining an AFS token along with the ticket by
running an external program automatically.

%prep
%setup

%build
PATH="/sbin:/bin:/usr/sbin:/usr/sbin:$PATH" \
%configure
%{__make}

%install
%{__rm} -rf %{buildroot}
%makeinstall

%clean
%{__rm} -rf %{buildroot}

%files
%defattr(-, root, root, 0755)
%doc NEWS README
%{_bindir}/*
%{_mandir}/*/*

%changelog
* Sun Jan 22 2006 Russ Allbery <rra@stanford.edu> 3.0-1
- New version for 3.0 release.
- Update description to include krenew.
- No longer build with --enable-reduced-depends.
* Sat Dec 31 2005 Russ Allbery <rra@stanford.edu> 2.9-1
- New version for 2.9 release.
- No longer generated via Autoconf, since the changelog has to be added.
* Sat Dec 10 2005 Russ Allbery <rra@stanford.edu> 2.8-2
- Incorporate into the package, remove Autoreq.
* Thu Oct 27 2005 Buck <buckh@> 2.8-1
- stole spec file (not recently) from
  http://svn.rpmforge.net/svn/trunk/rpms/nagios-plugins/nagios-plugins.spec
