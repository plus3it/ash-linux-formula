# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Rule ID:
# - service_restorecond_enabled
#
# Security identifiers:
# - CCE-26991-0
#
# Rule Summary: Enable the SELinux Context Restoration Service
#
# Rule Text: The restorecond service utilizes inotify to look for the 
#            creation of new files listed in the 
#            /etc/selinux/restorecond.conf configuration file. When a 
#            file is created, restorecond ensures the file receives the 
#            proper SELinux security context. The restorecond service 
#            can be enabled with the following command:
#
#################################################################

{%- set helperLoc = 'ash-linux/el6/SCAPonly/low/files' %}
{%- set scapId = 'CCE-26991-0' %}
{%- set svcPkg = 'policycoreutils' %}
{%- set svcName = 'restorecond' %}
{%- set notify_change = '''{{ svcName }}'' has been enabled' %}
{%- set notify_nochange = '''{{ svcName }}'' already enabled' %}

script_{{ scapId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ scapId }}.sh
    - cwd: '/root'

pkg_{{ scapId }}-{{ svcPkg }}:
  pkg.installed:
    - name: '{{ svcPkg }}'

svc_{{ scapId }}-{{ svcName }}Enabled:
  service.enabled:
    - name: '{{ svcName }}'
    - require: 
      - pkg: pkg_{{ scapId }}-{{ svcPkg }}

svc_{{ scapId }}-{{ svcName }}Running:
  service.running:
    - name: '{{ svcName }}'
    - require: 
      - service: svc_{{ scapId }}-{{ svcName }}Enabled
