Summary: A sender authentication milter supporting SPF and Sender ID
Name: enma
Version: 1.0.0
Release: 1
License: BSD
URL: http://sourceforge.net/projects/enma/
Group: Applications/Internet
Source0: enma-1.0.0.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildRequires: bind-libbind-devel
BuildRequires: sendmail-devel
Requires: bind-libs
Requires(post): chkconfig
Requires(preun): chkconfig

%description
ENMA is a program of domain authentication technologies. It authenticates 
message senders with SPF and/or Sender ID and inserts the 
Authentication-Results: field with authentication results.

%prep
%setup -q

%build
%configure --with-libbind-incdir=/usr/include/bind
make %{?_smp_mflags}

%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot}

mkdir -p %{buildroot}%{_initrddir}
install -m 755 enma/bin/rc.enma-centos %{buildroot}%{_initrddir}/enma
install -m 644 enma/etc/enma.conf.sample %{buildroot}%{_sysconfdir}/enma.conf

mkdir -p %{buildroot}%{_localstatedir}/run/enma/

%clean
rm -rf %{buildroot}

%post
/sbin/chkconfig --add enma

%preun
if [ $1 = 0 ] ; then
    /sbin/service enma stop > /dev/null 2>&1
    /sbin/chkconfig --del enma
fi

%postun
if [ $1 -ge 1 ] ; then
    /sbin/service enma condrestart > /dev/null 2>&1
fi

%files
%defattr(-, root, root, -)
%doc ChangeLog LICENSE LICENSE.ja README README.ja INSTALL INSTALL.ja TODO
%{_bindir}/*
%{_mandir}/*
%{_initrddir}/enma
%config %{_sysconfdir}/enma.conf
%attr(0750, daemon, daemon) %dir %{_localstatedir}/run/enma/

%changelog
* Thu Aug 28 2008 SUZUKI Takahiko <takahiko@iij.ad.jp>
- (1.0.0-1)
- public release

* Tue Aug 26 2008 SUZUKI Takahiko <takahiko@iij.ad.jp>
- (0.9.2-1)
- new upstream release

* Fri Aug 22 2008 SUZUKI Takahiko <takahiko@iij.ad.jp>
- (0.9.1-1)
- new upstream release

* Tue Aug 19 2008 Mitsuru Shimamura <simamura@iij.ad.jp>
- (0.9.0-1)
- internal beta release
