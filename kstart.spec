Name: kstart
Summary: Kerberos kinit variants supporting ticket refreshing
Version: 3.16
Release: 1%{?dist}
License: MIT
Group: System Environment/Base
URL: http://www.eyrie.org/~eagle/software/kstart/
Source: http://archives.eyrie.org/software/kerberos/%{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
BuildRequires: krb5-devel
Requires: krb5-libs
Vendor: Stanford University

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
%setup -q -n kstart-%{version}

%build
PATH="/sbin:/bin:/usr/sbin:/usr/bin:$PATH" \
%configure --enable-setpag
%{__make}

%install
%{__rm} -rf %{buildroot}
%makeinstall

%clean
%{__rm} -rf %{buildroot}

%files
%defattr(-, root, root, 0755)
%{_bindir}/*
%defattr(-, root, root, 0644)
%doc LICENSE NEWS README TODO
%{_mandir}/*/*

%changelog
* Mon Mar 29 2010 Andy Cobaugh <phalenor@bx.psu.edu> 3.16-1
- New version for 3.16 release.
- Require krb5-libs instead of krb5-workstation.

* Sat Aug 15 2008 Russ Allbery <rra@stanford.edu> 3.15-1
- New version for 3.15 release.

* Tue Jul 22 2008 Russ Allbery <rra@stanford.edu> 3.14-1
- New version for 3.14 release.
- Fix default file attributes for non-executables.
- Remove the BSD license; everything is under an MIT license.

* Wed May 28 2008 Russ Allbery <rra@stanford.edu> 3.13-1
- New version for 3.13 release.

* Wed Apr 23 2008 Russ Allbery <rra@stanford.edu> 3.12-1
- New version for 3.12 release.

* Tue Apr 10 2008 Russ Allbery <rra@stanford.edu> 3.11-1
- New version for 3.11 release.
- Add LICENSE and TODO to documentation.
- Build with --enable-setpag now that it no longer requires extra libraries.

* Sat Mar 3 2007 Russ Allbery <rra@stanford.edu> 3.9-1
- New version for 3.9 release.

* Sat Mar 3 2007 Russ Allbery <rra@stanford.edu> 3.8-1
- New version for 3.8 release.

* Sun Jan 28 2007 Russ Allbery <rra@stanford.edu> 3.7-1
- New version for 3.7 release.

* Wed Oct 04 2006 Russ Allbery <rra@stanford.edu> 3.6-1
- New version for 3.6 release.

* Tue Jun 13 2006 Russ Allbery <rra@stanford.edu> 3.5-1
- New version for 3.5 release.

* Mon Apr 10 2006 Russ Allbery <rra@stanford.edu> 3.3-1
- New version for 3.3 release.

* Sun Mar 05 2006 Russ Allbery <rra@stanford.edu> 3.2-1
- New version for 3.2 release.

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
