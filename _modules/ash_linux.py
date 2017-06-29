# -*- coding: utf-8 -*-
"""
Provide custom modules for ash-linux.

:maintainer: Loren Gordon <loren.gordon@plus3it.com>
"""
import os
import re
import spwd

import salt.utils

__virtualname__ = 'ash'


def __virtual__():
    if __grains__.get('kernel', '') == 'Linux':
        return __virtualname__
    else:
        return False, 'ash_linux module works only on Linux systems'


def _create_new_grub_file(remove):
    """
    Insert/remove fips argument from GRUB file in /etc/default.
    
    Args:
        remove:  (`obj`: `bool`)
        True if removing fips argument. False to add it.
    """
    if os.path.exists('/etc/default/grub'):
        with salt.utils.fopen('/etc/default/grub') as old_fle:
            with salt.utils.fopen('/etc/default/grub_new', 'w') as new_fle:
                for line in old_fle.xreadlines():
                    if line.startswith('GRUB_CMDLINE_LINUX') and remove:
                        new_fle.write(line.replace('fips=1 ', ''))
                    elif line.startswith('GRUB_CMDLINE_LINUX'):
                        new_fle.write(line.replace('boot=', 'fips=1 boot='))
                    else:
                        new_fle.write(line)
        __salt__['file.move']('/etc/default/grub_new', '/etc/default/grub')


def _get_dracutfips_pkgs():
    """
    Returns list of available dracut-fips pkgs to install. We currently
    resort to using an actual call to yum as Salt's pkg.list_repo_pkgs()
    does not look in repos that have been enabled like "enabled = 1"
    instead of "enabled=1".  Once that has been addressed in Salt, we can
    update this to use Salt's command.
    """
    cmd = "yum list available"
    available_pkgs = __salt__['cmd.run'](cmd, python_shell=False)
    return re.findall(r'\bdracut-fips[^.]*', available_pkgs)


def fips_disable():
    """
    Disables FIPS on RH/CentOS system. Note that you must reboot the
    system in order for FIPS to be disabled.  This routine prepares
    the system to disable FIPS.
    
    CLI Example:
    .. code-block:: bash
        salt '*' ash.fips_disable
    """

    # Remove dracut-fips installations.
    __salt__['pkg.remove']('dracut-fips')

    # Create a back-up of the FIPS boot-kernel.
    # The third index in the os.uname() tuple contains the release information.
    filename = "initramfs-" + os.uname()[2] + ".img"
    old_path = os.path.join("/boot", filename)
    new_path = os.path.join("/boot", filename + ".FIPS-bak")
    __salt__['file.move'](old_path, new_path)

    # Create a new boot-kernel.
    __salt__['cmd.run']("dracut -v", python_shell=False)

    # Update grub.cfg file to remove the fips argument.
    __salt__['cmd.run']("grubby --update-kernel=ALL --remove-args=fips=1")

    # Update GRUB command line entry to remove fips.
    _create_new_grub_file(True)

    ret = {
        'result': True,
        'comment': "FIPS set to disable. Reboot system to disable FIPS."
    }
    return ret


def fips_enable():
    """
    Enables FIPS on RH/CentOS system.  Note that you must reboot the
    system in order for FIPS to be disabled.  This routine prepares
    the system to disable FIPS.
    
    CLI Example:
    .. code-block:: bash
        salt '*' ash.fips_enable
    """

    # Install dracut-fips packages.
    __salt__['pkg.install'](",".join(_get_dracutfips_pkgs()))

    # Restore back-up of the FIPS boot-kernel.
    # The third index in the os.uname() tuple contains the release information.
    # If a backup file does not exist, run dracut to generate a new one.
    filename = "initramfs-" + os.uname()[2] + ".img.FIPS-bak"
    old_path = os.path.join("/boot", filename)
    if os.path.exists(old_path):
        new_path = os.path.join("/boot", filename[:-9])
        __salt__['file.move'](old_path, new_path)
    else:
        __salt__['cmd.run']("dracut -f")

    # Update grub.cfg file to add the fips agurment.
    __salt__['cmd.run']("grubby --update-kernel=ALL --args=fips=1")

    # Update GRUB command line entry to add fips.
    _create_new_grub_file(False)

    ret = {
        'result': True,
        'comment': "FIPS set to enable. Reboot system to enable FIPS."
    }
    return ret


def fips_status():
    """
    Returns the status of fips on the currently running system.
    
    Returns a `str` of "enabled" if FIPS is enabled. Otherwise,
    returns a `str` of "disabled".

    CLI Example:
    .. code-block:: bash
        salt '*' ash.fips_status
    """
    try:
        with salt.utils.fopen('/proc/sys/crypto/fips_enabled', 'r') as fle:
            val = fle.read().strip()
            if val == '1':
                return 'enabled'
            else:
                return 'disabled'
    except:
        return 'disabled'


def shadow_list_users():
    """
    Return a list of all shadow users.

    Will be superseded by ``shadow.list_users``, in the salt Oxygen release.

    CLI Example:
    .. code-block:: bash
        salt '*' ash.shadow_list_users
    """
    return sorted([user.sp_nam for user in spwd.getspall()])
