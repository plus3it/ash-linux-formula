# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Rule ID: audit_manual_logon_edits
# - service_acpid_disabled
#
# Security identifiers:
# - CCE-27061-1
#
# Rule Summary: Disable Advanced Configuration and Power Interface (acpid)
#
# Rule Text: The Advanced Configuration and Power Interface Daemon 
#            (acpid) dispatches ACPI events (such as power/reset button 
#            depressed) to userspace programs. ACPI support is highly 
#            desirable for systems in some network roles, such as 
#            laptops or desktops. For other systems, such as servers, it 
#            may permit accidental or trivially achievable denial of 
#            service situations and disabling it is appropriate.
#
#################################################################

{%- set scapId = 'CCE-27061-1' %}
{%- set helperLoc = 'ash-linux/el6/SCAPonly/low/files' %}
{%- set service = 'acpid' %}

script_{{ scapId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ scapId }}.sh
    - cwd: '/root'

{%- if salt['pkg.version'](service) %}
disable_{{ scapId }}-{{ service }}:
  service.disabled:
    - name: '{{ service }}'
    - onlyif: 'rpm -q --quiet {{ service }}'

dead_{{ scapId }}-{{ service }}:
  service.dead:
    - name: '{{ service }}'
    - onlyif: 'rpm -q --quiet {{ service }}'
{%- else %}
notify_{{ scapId }}-notInstalled:
  cmd.run:
    - name: 'printf "**************************************\n* The ACPI service is not installed. *\n* Nothing to do.                     *\n**************************************\n"'
{%- endif %}
