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


def _get_default_kernel():
    """Obtain default kernel from grubby command."""
    cmd = 'grubby --default-kernel'
    return __salt__['cmd.run'](cmd, python_shell=True, output_loglevel='quiet')


def _get_boot_mount():
    """Obtain mount to path that kernel is located in."""
    boot_path = _get_default_kernel()
    boot_path = boot_path[:boot_path.rindex('/')] or '/'
    cmd = 'findmnt -no source -T ' + boot_path
    return __salt__['cmd.run'](cmd, python_shell=True, output_loglevel='quiet')


def _modify_grub_file(rmv_fips_arg):
    """
    Insert/remove fips argument from GRUB file in /etc/default.

    Args:
        rmv_fips_arg:  (`obj`: `bool`)
        True if removing fips argument. False to add it.
    """
    filepath = '/etc/default/grub'
    if rmv_fips_arg:
        result = __salt__['file.replace'](filepath, 'fips=1[ ]', '')
    else:
        grub_marker = 'GRUB_CMDLINE_LINUX="'
        grub_args = []
        check = __salt__['file.search'](filepath, 'boot=')
        if not check:
            # No boot= in grub, so find mount where kernel is located.
            boot_mount = _get_boot_mount()
            # Add boot= argument.
            grub_args.append('boot={0} '.format(boot_mount))

        check = __salt__['file.search'](filepath, 'fips=1')
        if not check:
            grub_args.append('fips=1 ')

        if grub_args:
            result = __salt__['file.replace'](
                filepath, grub_marker,
                '{0}{1}'.format(grub_marker, ''.join(grub_args))
            )
        else:
            result = None

    return result


def _is_fips_in_kernel():
    """Checks image file for fips module."""
    filename = "initramfs-" + os.uname()[2] + ".img"
    filepath = os.path.join("/boot", filename)
    cmd = 'lsinitrd -m {0} | grep fips'.format(filepath)
    result = __salt__['cmd.run'](
        cmd, python_shell=True, output_loglevel='quiet') == 'fips'
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
    """Obtain arguments line in grubby command."""
    cmd = 'grubby --info=' + _get_default_kernel() + ' | grep args='
    return __salt__['cmd.run'](cmd, python_shell=True, output_loglevel='quiet')


def _rollback_fips_disable(installed_fips_pkgs):
    """
    Rollback the actions of fips_disable() upon a thrown error.

    Args:
        installed_fips_pkgs:  (`obj`: `list`)
        List of installed dracut-fips packages that were removed
        during the process of running fips_disable().
    """
    __salt__['pkg.install'](installed_fips_pkgs)

    if not _is_fips_in_kernel():
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
    ret = { 'result': True }
    old = {}
    new = {}

    try:
        # Remove dracut-fips installations.
        installed_fips_pkgs = _get_installed_dracutfips_pkgs()
        if 'dracut-fips' in installed_fips_pkgs:
            __salt__['pkg.remove']('dracut-fips')
            old['Packages'] = installed_fips_pkgs

        # If fips is in kernel, create a new boot-kernel.
        if _is_fips_in_kernel():
            _move_boot_kernel(False)
            __salt__['cmd.run']("dracut -f", python_shell=False)

        # Update grub.cfg file to remove the fips argument.
        grub_args = _get_grub_args()
        if 'fips=1' in grub_args:
            cmd = 'grubby --update-kernel=ALL --remove-args=fips=1'
            __salt__['cmd.run'](cmd, python_shell=False)
            new['grubby'] = cmd

        # Update GRUB command line entry to remove fips.
        diff = _modify_grub_file(True)
        if diff:
            new['/etc/default/grub'] = diff
    except Exception:
        _rollback_fips_disable(installed_fips_pkgs)
        ret['result'] = False
        ret['changes'] = {}
        ret['comment'] = 'Unable to change state of system to FIPS-disabled.'
    else:
        if old:
            ret['changes'] = {'old': old}
            ret['comment'] = 'FIPS has been toggled to off.'
        if new:
            if 'changes' in ret:
                ret['changes'].update({'new': new})
            else:
                ret['changes'] = {'new': new}
            ret['comment'] = 'FIPS has been toggled to off.'
        if fips_status() == 'enabled':
            msg = ' Reboot system to place into FIPS-disabled state.'
            if 'comment' in ret:
                ret['comment'] = ret['comment'] + msg
            else:
                ret['comment'] = msg[1:]
        if 'changes' not in ret and 'comment' not in ret:
            ret['comment'] = 'FIPS mode is already disabled. No changes.'
    finally:
        return ret


def _rollback_fips_enable():
    """Rollback the actions of fips_enable() upon a thrown error."""
    __salt__['pkg.remove']('dracut-fips')

    if _is_fips_in_kernel():
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
    ret = { 'result': True }
    new = {}

    try:
        # Install dracut-fips package.
        installed_fips_pkgs = _get_installed_dracutfips_pkgs()
        if 'dracut-fips' not in installed_fips_pkgs:
            __salt__['pkg.install']('dracut-fips')
            installed_fips_pkgs = _get_installed_dracutfips_pkgs()
            new['Packages'] = installed_fips_pkgs

        # If fips is not in kernel, create a new boot-kernel.
        if not _is_fips_in_kernel():
            _move_boot_kernel(False)
            __salt__['cmd.run']("dracut -f", python_shell=False)

        # Update grub.cfg file to add the fips and boot agurments.
        grubby_args = []
        grub_args = _get_grub_args()
        if 'fips=1' not in grub_args:
            grubby_args.append('fips=1')
        if 'boot=' not in grub_args:
            grubby_args.append('boot={0}'.format(_get_boot_mount()))
        if grubby_args:
            cmd = 'grubby --update-kernel=ALL --args="{0}"'.format(
                ' '.join(grubby_args)
            )
            __salt__['cmd.run'](cmd, python_shell=False)
            new['grubby'] = cmd

        # Update GRUB command line entry to add fips.
        diff = _modify_grub_file(False)
        if diff:
            new['/etc/default/grub'] = diff
    except Exception:
        _rollback_fips_enable()
        ret['result'] = False
        ret['comment'] = 'Unable to change state of system to FIPS-enabled.'
    else:
        if new:
            ret['changes'] = {'new': new}
            ret['comment'] = 'FIPS has been toggled to on.'
        if fips_status() == 'disabled':
            msg = ' Reboot system to place into FIPS-enabled state.'
            if 'comment' in ret:
                ret['comment'] = ret['comment'] + msg
            else:
                ret['comment'] = msg[1:]
        if 'changes' not in ret and 'comment' not in ret:
            ret['comment'] = 'FIPS mode is already enabled. No changes.'
    finally:
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
