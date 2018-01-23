
# DSEFix
## Windows x64 Driver Signature Enforcement Overrider

For more info see Defeating x64 Driver Signature Enforcement http://www.kernelmode.info/forum/viewtopic.php?f=11&t=3322.

# System Requirements

x64 Windows Vista/7/8/8.1/10.

Windows 8.1/10: warning, see PatchGuard note below.

DSEFix designed only for x64 Windows.

Administrative privilege is required.

# Build 

DSEFix comes with full source code.
In order to build from source you need Microsoft Visual Studio 2013 U4 and later versions.

# How it work

It uses WinNT/Turla VirtualBox kernel mode exploit technique to overwrite global system variable controlling DSE behavior, which itself located in kernel memory space. Prior to Windows 8 it is ntoskrnl!g_CiEnabled - a boolean variable (0 disabled, 1 enabled) and starting from Windows 8 it is CI.DLL!g_CiOptions - combination of flags, where value of 6 is default options and value of 0 is equal to "no integrity checks". If you run DSEFix without parameters it will attempt to disable DSE in a way depending on the system version. If you run DSEFix with "-e" parameter (without quotes) it will attempt to restore DSE controlling variable to default state.

# PatchGuard incompatibility

Warning, starting from Windows 8.1 CI.DLL variables protected by Kernel Patch Protection (PatchGuard) as a generic data region. This doesn't mean instant PatchGuard response (BSOD) but will eventually lead to it when PatchGuard will be able to detect modification fact (doesn't really matter if you restore original state). Time of reaction is almost random. It can be almost instanst, or take a hour, two or four etc.

# Deprecation

DSEFix based on old Oracle VirtualBox driver which was created in 2008. This driver wasn't designed to be compatible with newest Windows operation system versions and may work incorrectly. Because DSEFix entirely based on this exact VirtualBox driver version LPE it is not wise to use it on newest version of Windows. Consider this repository as depricated/abandonware. The only possible updates can be related only to DSEFix software itself.

# Authors

(c) 2014 - 2018 DSEFix Project
