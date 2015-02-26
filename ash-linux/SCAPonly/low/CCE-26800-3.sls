# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Security identifiers:
# - CCE-26800-3
#
# Rule ID: kernel_module_hfs_disabled
#
# Rule Summary: Disable Mounting of hfs
#
# Rule Text: Linux kernel modules which implement filesystems that are 
#            not needed by the local system should be disabled.
#
#################################################################

{%- set scapId = 'CCE-26800-3' %}
{%- set helperLoc = 'ash-linux/SCAPonly/low/files' %}
{%- set moduleConf = '/etc/modprobe.d/hfs.conf' %}

script_{{ scapId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ scapId }}.sh
    - cwd: '/root'

append_{{ scapId }}-directive:
  file.append:
    - name: '{{ moduleConf }}'
    - text: |
        # Added per SCAP-ID {{ scapId }}
        install hfs /bin/false
    - unless: 'grep hfs {{ moduleConf }}'
