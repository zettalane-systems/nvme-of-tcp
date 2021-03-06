%define Dist %(echo $RPM_DIST)
%define Mods %(echo "$RPM_MODS")
%define	_mayadir	/opt/zettalane
Summary: NVMEoF TCP Host Drivers
Name: kmod-nvme-tcp
Version: 1.0
Release: 1
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
	if [ -e ${moddir}/${mod}.${kver} ]; then
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
	mod_list=$(ls ${moddir}/${mod}.*${flav}* 2> /dev/null)
	for m in ${mod_list}; do
		pkgver=$(echo $m | sed -nr 's/[^0-9]*([0-9.-]*).*/\1/p')
		pkgver=$(echo $pkgver | sed 's/[.-]$//') # Trailing . or -
		if [[ "$kver" == ${pkgver}* ]] ; then
			modbase=$(basename $m)
			modbase=${modbase##$mod.}
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
	if [ "$mod" = "nvme-fabrics.ko" ] ; then
		echo "Saving distribution nvme module $mod."
		mv -f ${kerndir}/${mod}.xz ${moddir}
	fi
	cp ${moddir}/${mod}.${modbase} $kerndir/$mod
done

depmod -a

%clean
[ ${RPM_BUILD_ROOT} != "/" ] && rm -rf $RPM_BUILD_ROOT

%files
%defattr (-, root, root)
%dir %_mayadir
%dir %_mayadir/bin
%_mayadir/bin/nvme
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
	if [ "$mod" = "nvme-fabrics.ko" ] ; then
		mv ${moddir}/nvme-fabrics.ko.xz ${kroot}/${kver}/kernel/drivers/nvme/host
	fi
	rm -f $kerndir/$mod
done
depmod -a
exit 0

%changelog
* Tue Aug 21 2018 suprasam [1.0-1]
- release based on 4.11 driver

