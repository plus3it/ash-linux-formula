# -*- coding: utf-8 -*-
"""
Provide custom state module for ash-linux.

:maintainer: Loren Gordon <loren.gordon@plus3it.com>
"""
from salt.exceptions import SaltInvocationError

__virtualname__ = 'ash'


def __virtual__():
    if __grains__.get('kernel', '') == 'Linux':
        return __virtualname__
    else:
        return False, 'ash_linux module works only on Linux systems'


def fips_state(name, value):
    '''
    Prepare a system to be FIPS-enabled or FIPS-disabled.

    name
        assigned name to the process

    value
        Status for FIPS - either 'enabled' or 'disabled'.
        For example:
        .. code-block:: yaml
            fips_disable:
                ash.fips_state:
                    - value: disabled
    '''
    ret = {'name': name,
           'changes': {},
           'comment': '',
           'state': value,
           'result': True}

    if __opts__['test']:
        ret['comment'] = 'System is now FIPS-{0}.'.format(value)
        return ret

    if value == 'enabled':
        ret.update(__salt__['ash.fips_enable']())
    elif value == 'disabled':
        ret.update(__salt__['ash.fips_disable']())
    else:
        raise SaltInvocationError(
            '"{0}" is not a valid `value`. Must be "enabled" or "disabled"'
            .format(value)
        )

    return ret
