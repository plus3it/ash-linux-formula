# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Security identifiers:
# - CCE-27011-6
#
# Rule ID: bootloader_nousb_argument
#
# Rule Summary: Disable Kernel Support for USB via Bootloader Configuration
#
# Rule Text: Disabling the USB subsystem within the Linux kernel at
#            system boot will protect against potentially malicious USB
#            devices, although it is only practical in specialized
#            systems.
#
#################################################################

{%- set scapId = 'CCE-27011-6' %}
{%- set helperLoc = 'ash-linux/el6/SCAPonly/low/files' %}
{%- set grubCfgFile = '/boot/grub/grub.conf' %}

script_{{ scapId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ scapId }}.sh
    - cwd: '/root'

# Disable USB at kernel load
{%-
    if salt['file.search'](grubCfgFile, 'kernel', ignore_if_missing=True) and not
       salt['file.search'](grubCfgFile, 'kernel.*nousb', ignore_if_missing=True)
%}

file_{{ scapId }}-repl:
  file.replace:
    - name: '{{ grubCfgFile }}'
    - pattern: '(?P<srctok>kernel.*$)'
    - repl: '\g<srctok> nousb'

notify_{{ scapId }}-audit:
  cmd.run:
    - name: 'printf "Note: Disabled USB support at IPL via addition of\n      ''nousb'' to {{ grubCfgFile }}\n"'
    - unless: 'file_{{ scapId }}-audit'

{%- else %}

status_{{ scapId }}:
  cmd.run:
    - name: 'echo "Auditing already enabled at boot"'

{%- endif %}
