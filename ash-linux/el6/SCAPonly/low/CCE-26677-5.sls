# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Security identifiers:
# - CCE-26677-5
#
# Rule ID: kernel_module_udf_disabled
#
# Rule Summary: Disable Mounting of udf
#
# Rule Text: Linux kernel modules which implement filesystems that are 
#            not needed by the local system should be disabled.
#
#################################################################

{%- set scapId = 'CCE-26677-5' %}
{%- set helperLoc = 'ash-linux/el6/SCAPonly/low/files' %}
{%- set fsDrv = 'udf' %}
{%- set moduleConf = '/etc/modprobe.d/' + fsDrv + '.conf' %}

script_{{ scapId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ scapId }}.sh
    - cwd: '/root'

append_{{ scapId }}-directive:
  file.append:
    - name: '{{ moduleConf }}'
    - text: |
        # Added per SCAP-ID {{ scapId }}
        install {{ fsDrv }} /bin/false
    - unless: 'grep {{ fsDrv }} {{ moduleConf }}'
