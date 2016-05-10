# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Rule ID: audit_manual_logon_edits
# - service_irqbalance_enabled
#
# Security identifiers:
# - CCE-26990-2
#
# Rule Summary: Enable IRQ Balance (irqbalance)
#
# Rule Text: The irqbalance service optimizes the balance between power 
#            savings and performance through distribution of hardware 
#            interrupts across multiple processors.  In an environment 
#            with multiple processors (now common), the irqbalance 
#            service provides potential speedups for handling interrupt 
#            requests (helpful in systems with enhanced audit-collection 
#            enabled).
#
#################################################################

{%- set helperLoc = 'ash-linux/el6/SCAPonly/low/files' %}
{%- set scapId = 'CCE-26990-2' %}
{%- set service = 'irqbalance' %}

script_{{ scapId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ scapId }}.sh
    - cwd: '/root'

script_{{ scapId }}-CPUcount:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ scapId }}_helper.sh
    - cwd: '/root'

pkg_{{ scapId }}-{{ service }}:
  pkg.installed:
    - name: '{{ service }}'

enable_{{ scapId }}-{{ service }}:
  service.enabled:
    - name: '{{ service }}'
    - unless: 'pkg_{{ scapId }}-{{ service }}'
    - onlyif: 'script_{{ scapId }}-CPUcount'

running_{{ scapId }}-{{ service }}:
  service.running:
    - name: '{{ service }}'
    - onlyif: 'script_{{ scapId }}-CPUcount'
