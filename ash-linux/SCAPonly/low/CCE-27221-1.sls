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

script_CCE-27221-1-describe:
  cmd.script:
  - source: salt://SCAPonly/low/files/CCE-27221-1.sh
  - cwd: '/root'

{% set TargFile = '/etc/sysconfig/prelink' %}

{% if salt['pkg.version']('prelink') %}
  {% if salt['file.search'](TargFile, '^PRELINKING=') %}
file_CCE-27221-1-alter:
  file.replace:
  - name: '{{ TargFile }}'
  - pattern: '^PRELINKING=.*'
  - repl: 'PRELINKING=no'
  {% else %}
file_CCE-27221-1-alter:
  file.append:
  - name: '{{ TargFile }}'
  - text: 'PRELINKING=no'
  {% endif %}
{% else %}
notify_CCE-27221-1:
  cmd.run:
  - name: 'echo "NOTICE: the prelink utilities not installed. Applying precautionary remediation."'
file_CCE-27221-1-touch:
  file.touch:
  - name: '{{ TargFile }}'
file_CCE-27221-1-alter:
  file.append:
  - name: '{{ TargFile }}'
  - text: 'PRELINKING=no'
  - unless: file_CCE-27221-1-touch
{% endif %}

