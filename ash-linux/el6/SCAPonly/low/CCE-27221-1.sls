# This Salt test/lockdown implements a SCAP item that has not yet been 
# merged into the DISA-published STIGS
#
# Security identifiers:
# - CCE-27221-1
#
# Rule Summary: disable_prelink
#
# Rule Text: The prelinking feature changes binaries in an attempt to 
#            decrease their startup time. The prelinking feature can
#            interfere with the operation of AIDE, because it changes
#            binaries.
#
###########################################################################

{%- set scapId = 'CCE-27221-1' %}
{%- set helperLoc = 'ash-linux/el6/SCAPonly/low/files' %}

script_{{ scapId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ scapId }}.sh
    - cwd: '/root'

{%- set TargFile = '/etc/sysconfig/prelink' %}

{%- if salt['pkg.version']('prelink') %}
  {%- if salt['file.search'](TargFile, '^PRELINKING=') %}
file_{{ scapId }}-alter:
  file.replace:
    - name: '{{ TargFile }}'
    - pattern: '^PRELINKING=.*'
    - repl: 'PRELINKING=no'
  {%- else %}
file_{{ scapId }}-alter:
  file.append:
    - name: '{{ TargFile }}'
    - text: 'PRELINKING=no'
  {%- endif %}
{%- else %}
notify_{{ scapId }}:
  cmd.run:
    - name: 'echo "NOTICE: the prelink utilities not installed. Applying precautionary remediation."'
file_{{ scapId }}-touch:
  file.touch:
    - name: '{{ TargFile }}'
file_{{ scapId }}-alter:
  file.append:
    - name: '{{ TargFile }}'
    - text: 'PRELINKING=no'
    - unless: file_{{ scapId }}-touch
{%- endif %}
