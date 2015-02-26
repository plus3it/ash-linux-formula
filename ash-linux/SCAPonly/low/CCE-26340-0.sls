# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Security identifiers:
# - CCE-26340-0
#
# Rule ID: kernel_module_cramfs_disabled
#
# Rule Summary: Disable Mounting of cramfs
#
# Rule Text: Linux kernel modules which implement filesystems that are 
#            not needed by the local system should be disabled.
#
#################################################################

{%- set scapId = 'CCE-26340-0' %}
{%- set helperLoc = 'ash-linux/SCAPonly/low/files' %}
{%- set moduleConf = '/etc/modprobe.d/cramfs.conf' %}

script_{{ scapId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ scapId }}.sh
    - cwd: '/root'

append_{{ scapId }}-directive:
  file.append:
    - name: '{{ moduleConf }}'
    - text: |
        # Added per SCAP-ID {{ scapId }}
        install cramfs /bin/false
    - unless: 'grep cramfs {{ moduleConf }}'
