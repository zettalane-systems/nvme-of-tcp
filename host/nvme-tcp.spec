%define Dist %(echo $RPM_DIST)
%define Mods %(echo "$RPM_MODS")
%define	_mayadir	/opt/zettalane
Summary: NVMEoF TCP Host Drivers
Name: kmod-nvme-tcp
Version: 1.0
Release: 2
Group: System Environment/Kernel
License: GPL
Vendor: ZettaLane
Source: kmod-nvme-tcp-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-root
Requires: kernel >= 3.10.0-514
Requires(post,postun): module-init-tools
%description
The driver modules required to provide TCP transport for NVMe over Fabrics.
The configuration is similar to the any other transport configured for nvmet.
It also provides updated nvme cli for connecting over tcp transport.

%prep
%setup -q

%install
rm -rf $RPM_BUILD_ROOT
mkdir ${RPM_BUILD_ROOT}
cp -pr opt ${RPM_BUILD_ROOT}

%pre
if [ "$(uname -m)" != "%{_target_cpu}" ]; then
	echo "ERROR: This package is built for %{_target_cpu} machines only. Exiting."
	exit 1
fi


%post
kver=$(uname -r)
kroot="/lib/modules"
kerndir=${kroot}/${kver}/kernel/drivers/nvme/host
optdir=/opt/zettalane
bindir="$optdir/bin"
moddir="$optdir/modules"
modbase=""

# Use exact driver module or try a matching module
get_mod_base() {
	mod=$1
	if [ -e ${moddir}/${mod}-${kver} ]; then
		modbase=${kver}
		return
	fi

	# Gather list of modules and attempt to see which one succeeds
	flav=$(echo $kver | tr -d '[0-9].-')
	if [ "%{Dist}" = "rhel6" ] ; then
		flav=el6
	fi
	if [ "%{Dist}" = "rhel7" ] ; then
		flav=el7
	fi
	# No double quotes too for ls here; otherwise * is not expanded
	mod_list=$(ls ${moddir}/${mod}*${flav}* 2> /dev/null)
	for m in ${mod_list}; do
		pkgver=$(echo $m | sed -nr 's/[^0-9]*([0-9.-]*).*/\1/p')
		pkgver=$(echo $pkgver | sed 's/[.-]$//') # Trailing . or -
		if [[ "$kver" == ${pkgver}* ]] ; then
			modbase=$(basename $m)
			modbase=${modbase##$mod[.-]}
			return
		fi
	done

}

get_mod_base nvme-tcp.ko

if [ -z "${modbase}" ]; then
	echo "ERROR: No matching NVME TCP driver modules for this kernel $(uname -r)."
	echo "       Contact Support for updated driver modules."
	exit 1
fi

[ ! -d "$kerndir" ] && mkdir -p $kerndir
for mod in %Mods; do
	echo "Saving distribution nvme module $mod."
	mv -f ${kerndir}/${mod}.xz ${moddir}
	cp ${moddir}/${mod}-${modbase} $kerndir/$mod
done

depmod -a

%clean
[ ${RPM_BUILD_ROOT} != "/" ] && rm -rf $RPM_BUILD_ROOT

%files
%defattr (-, root, root)
%dir %_mayadir
%dir %_mayadir/bin
%dir %_mayadir/modules
%_mayadir/modules/*


%preun
exit 0

%postun
[ "$1" != "0" ] && exit 0
optdir=/opt/zettalane
docdir="$optdir/docs"
moddir="$optdir/modules"
kroot="/lib/modules"
kver=$(uname -r)
kerndir=${kroot}/${kver}/kernel/drivers/nvme/host

for mod in %Mods; do
	rm -f $kerndir/$mod
	mv ${moddir}/${mod}.xz ${kroot}/${kver}/kernel/drivers/nvme/host
done
depmod -a
exit 0

%changelog
* Sun Feb 7 2021 suprasam [1.1-2]
-  include rhel 7.9 kernel

* Thu May 7 2020 suprasam [1.1-1]
-  release based on Lightbits nvme-tcp 

* Tue Aug 21 2018 suprasam [1.0-1]
- release based on 4.11 driver

