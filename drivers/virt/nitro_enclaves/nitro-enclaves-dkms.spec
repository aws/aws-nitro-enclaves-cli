%{?!module_name: %define module_name nitro-enclaves}
%{?!version: %define version 1.0}
Name:		%{module_name}
Version:	%{version}
Release:	1%{?dist}
Summary:	Nitro enclaves kernel driver

License:	GPL-2.0
Source0:	%{module_name}-%{version}.tar.bz2
BuildRequires:	%kernel_module_package_buildreqs

%kernel_module_package default

%description
This package contains the Nitro Enclaves kernel driver
meant for mananging enclaves lifecycle.

%prep
%setup -c %{name}
set -- *
mkdir source
mv "$@" source/
mkdir obj

%build
for flavor in %flavors_to_build; do
	echo $flavor
	rm -rf obj/$flavor
	cp -r source obj/$flavor
	make -C %{kernel_source $flavor} M=$PWD/obj/$flavor
done

%install
export INSTALL_MOD_PATH=$RPM_BUILD_ROOT
export INSTALL_MOD_DIR=extra/%{name}
for flavor in %flavors_to_build ; do
	make -C %{kernel_source $flavor} modules_install \
		M=$PWD/obj/$flavor
done
