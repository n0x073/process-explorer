# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Process Exp contributors

Name:           process-exp
Version:        1.0
Release:        1%{?dist}
Summary:        Process manager for Linux inspired by Sysinternals Process Explorer

License:        GPL-3.0-or-later
URL:            https://github.com/n0x073/process-explorer
Source0:        %{url}/archive/v%{version}/%{name}-%{version}.tar.gz

BuildRequires:  gcc-c++
BuildRequires:  cmake
BuildRequires:  cmake(Qt6Widgets)
BuildRequires:  cmake(Qt6DBus)
BuildRequires:  desktop-file-utils

# pkexec is used to retry actions on processes of other users
Recommends:     polkit

%description
Process Exp shows running processes as a tree and highlights them by
category (services, own processes, Flatpak apps, kernel threads, new and
exiting processes). It lists the open file descriptors, sockets and mapped
libraries of a process, shows per-process threads, network connections,
security context and environment. It can kill, suspend and restart
processes and change their priority. All data is read directly from /proc.

%prep
%autosetup -n process-explorer-%{version}

%build
%cmake
%cmake_build

%install
%cmake_install
# shipped through %%license instead
rm %{buildroot}%{_datadir}/licenses/%{name}/LICENSE

%check
desktop-file-validate %{buildroot}%{_datadir}/applications/%{name}.desktop

%files
%license LICENSE
%doc README.md
%{_bindir}/%{name}
%{_datadir}/applications/%{name}.desktop

%changelog
* Mon Oct 19 2026 John Doe <72650981+n0x073@users.noreply.github.com> - 1.0-1
- Initial package
