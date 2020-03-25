%define _enclave_image enclave_vtoken.eif
%define _enclave_image_dst aws_enclave_images

Summary:    AWS Nitro Enclave vtoken
Name:       aws-nitro-enclaves-vtoken
Version:    1.0
Release:    1%{?dist}

License:    Amazon Proprietary

BuildArch: x86_64

Source0: aws-nitro-enclaves-vtoken.tar.gz

Requires:  aws-nitro-enclaves-cli

%description
AWS Nitro Vtoken enclave image

%prep
%setup -c %{name}

%build

%install
install -D -m 0644 %{_enclave_image} %{buildroot}/%{_datadir}/%{_enclave_image_dst}/%{_enclave_image}


%files
%defattr(644,root,root,644)

%{_datadir}/%{_enclave_image_dst}/%{_enclave_image}

%changelog
* Wed Mar 25 2020 Alexandru Gheroghe <aggh@amazon.com> - 1.0-2
- Intial version for the Eif spec
