# -*- coding: utf-8 -*-
"""
Provide custom modules for ash-linux.

:maintainer: Loren Gordon <loren.gordon@plus3it.com>
"""
import spwd

__virtualname__ = 'ash'


def __virtual__():
    if __grains__.get('kernel', '') == 'Linux':
        return __virtualname__
    else:
        return False, 'ash_linux module works only on linux systems'


def shadow_list_users():
    """
    Return a list of all shadow users.

    Will be superseded by ``shadow.list_users``, in the salt Oxygen release.

    CLI Example:
    .. code-block:: bash
        salt '*' ash.shadow_list_users
    """
    return sorted([user.sp_nam for user in spwd.getspall()])
