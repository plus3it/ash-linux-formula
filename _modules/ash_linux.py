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


def _move_boot_kernel(restore_bak):
    """
    Create/restore backup of boot-kernel file.

    Args:
        restore_bak:  (`obj`: `bool`)
        True if restoring backup of boot-kernel. False to create a backup.
    """
    if restore_bak:
        filename = "initramfs-" + os.uname()[2] + ".img.bak"
        new_path = os.path.join("/boot", filename[:-4])
    else:
        filename = "initramfs-" + os.uname()[2] + ".img"
        new_path = os.path.join("/boot", filename + ".bak")

    old_path = os.path.join("/boot", filename)
    if os.path.exists(old_path):
        __salt__['file.move'](old_path, new_path)

    return old_path


def _modify_grub_file(rmv_fips_arg):
    """
    Insert/remove fips argument from GRUB file in /etc/default.
    
    Args:
        rmv_fips_arg:  (`obj`: `bool`)
        True if removing fips argument. False to add it.
    """
    filepath = '/etc/default/grub'
    if rmv_fips_arg:
        result = __salt__['file.replace'](
            filepath, 'fips=1', '', show_changes=False
        )
    else:
        result = __salt__['file.replace'](
            filepath, 'GRUB_CMDLINE_LINUX="',
            'GRUB_CMDLINE_LINUX="fips=1 ',
            show_changes=False
        )
    return result


def _get_installed_dracutfips_pkgs():
    """
    Returns list of available dracut-fips pkgs to install. We currently
    resort to using an actual call to yum as Salt's pkg.list_repo_pkgs()
    does not look in repos that have been enabled like "enabled = 1"
    instead of "enabled=1".  Once that has been addressed in Salt, we can
    update this to use Salt's command.
    """
    cmd = "yum list installed"
    available_pkgs = __salt__['cmd.run'](cmd, python_shell=False)
    return re.findall(r'\bdracut-fips[^.]*', available_pkgs)


def _get_grub_args():
    cmd = "grubby --info=ALL | grep args="
    return __salt__['cmd.run'](cmd, python_shell=True)


def _rollback_fips_disable(installed_fips_pkgs):
    """
    Rollback the actions of fips_disable() upon a thrown error.

    Args:
        installed_fips_pkgs:  (`obj`: `list`)
        List of installed dracut-fips packages that were removed
        during the process of running fips_disable().
    """
    __salt__['pkg.install'](installed_fips_pkgs)
    _move_boot_kernel(True)

    grub_bak = '/etc/default/grub.bak'
    if os.path.exists(grub_bak):
        __salt__['file.move'](grub_bak, '/etc/default/grub')

    __salt__['cmd.run'](
        "grubby --update-kernel=ALL --args=fips=1",
        python_shell=False
    )


def fips_disable():
    """
    Disables FIPS on RH/CentOS system. Note that you must reboot the
    system in order for FIPS to be disabled.  This routine prepares
    the system to disable FIPS.
    
    CLI Example:
    .. code-block:: bash
        salt '*' ash.fips_disable
    """
    installed_fips_pkgs = _get_installed_dracutfips_pkgs()
    ret = {
        'result': True,
        'changes': {'old': {}, 'new': {}},
        'comment': ("FIPS has been toggled to off.",
                    "Reboot system to place into FIPS-disabled state.")
    }

    try:
        # Remove dracut-fips installations.
        installed_fips_pkgs = _get_installed_dracutfips_pkgs()
        if 'dracut-fips' in installed_fips_pkgs:
            __salt__['pkg.remove']('dracut-fips')
            ret['changes']['old'].update({'Packages': installed_fips_pkgs})

        # Create a back-up of the FIPS boot-kernel.
        # The third index in the os.uname() tuple contains the release information.
        _move_boot_kernel(False)

        # Create a new boot-kernel.
        __salt__['cmd.run']("dracut -f", python_shell=False)

        # Update grub.cfg file to remove the fips argument.
        grub_args = _get_grub_args()
        if 'fips=1' in grub_args:
            cmd = 'grubby --update-kernel=ALL --remove-args=fips=1'
            __salt__['cmd.run'](cmd, python_shell=False)
            ret['changes']['new'].update({'grubby': cmd})

        # Update GRUB command line entry to remove fips.
        if _modify_grub_file(True):
            ret['changes']['old'].update({'/etc/default/grub': {
                'GRUB_CMDLINE_LINUX': 'fips=1'
            }})
    except:
        _rollback_fips_disable(installed_fips_pkgs)
        ret['result'] = False
        ret['changes'] = {}
        ret['comment'] = 'Unable to change state of system to FIPS-disabled.'
    finally:
        return ret


def _rollback_fips_enable():
    """Rollback the actions of fips_enable() upon a thrown error."""
    __salt__['pkg.remove']('dracut-fips')
    _move_boot_kernel(True)

    grub_bak = '/etc/default/grub.bak'
    if os.path.exists(grub_bak):
        __salt__['file.move'](grub_bak, '/etc/default/grub')

    __salt__['cmd.run'](
        "grubby --update-kernel=ALL --remove-args=fips=1",
        python_shell=False
    )


def fips_enable():
    """
    Enables FIPS on RH/CentOS system.  Note that you must reboot the
    system in order for FIPS to be disabled.  This routine prepares
    the system to disable FIPS.
    
    CLI Example:
    .. code-block:: bash
        salt '*' ash.fips_enable
    """
    ret = {
        'result': True,
        'changes': {'old': {}, 'new': {}},
        'comment': ("FIPS has been toggled to on.",
                    "Reboot system to place into FIPS-enabled state.")
    }

    try:
        # Install dracut-fips package.
        installed_fips_pkgs = _get_installed_dracutfips_pkgs()
        if 'dracut-fips' not in installed_fips_pkgs:
            __salt__['pkg.install']('dracut-fips')
            installed_fips_pkgs = _get_installed_dracutfips_pkgs()
            ret['changes']['new'].update({'Packages': installed_fips_pkgs})

        # Restore back-up of the FIPS boot-kernel.
        # The third index in the os.uname() tuple contains the release information.
        _move_boot_kernel(False)

        # Run dracut to generate a new boot-kernel.
        __salt__['cmd.run']("dracut -f", python_shell=False)

        # Update grub.cfg file to add the fips agurment.
        grub_args = _get_grub_args()
        if 'fips=1' not in grub_args:
            cmd = 'grubby --update-kernel=ALL --args=fips=1'
            __salt__['cmd.run'](cmd, python_shell=False)
            ret['changes']['new'].update({'grubby': cmd})

        # Update GRUB command line entry to add fips.
        if _modify_grub_file(False):
            ret['changes']['new'].update({'/etc/default/grub': {
                'GRUB_CMDLINE_LINUX': 'fips=1'
            }})
    except:
        _rollback_fips_enable()
        ret['result'] = False
        ret['changes'] = {}
        ret['comment'] = 'Unable to change state of system to FIPS-enabled.'

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
            return 'enabled' if fle.read().strip() == '1' else 'disabled'
    except (IOError, FileNotFoundError):
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
