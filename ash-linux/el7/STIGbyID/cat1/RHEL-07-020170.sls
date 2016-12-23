# Finding ID:	RHEL-07-020170
# Version:	RHEL-07-020170_rule
# SRG ID:	SRG-OS-000405-GPOS-00184
# Finding Level:	high
#
# Rule Summary:
#	Operating systems handling data requiring data-at-rest
#	protections must employ cryptographic mechanisms to prevent
#	unauthorized disclosure and modification of the information
#	at rest.
#
# CCI-002476
# CCI-001199
#    NIST SP 800-53 Revision 4 :: SC-28 (1)
#    NIST SP 800-53 :: SC-28
#    NIST SP 800-53A :: SC-28.1
#    NIST SP 800-53 Revision 4 :: SC-28
#
#################################################################
{%- set stig_id = 'RHEL-07-020170' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat1/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set corePkg = 'cryptsetup' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Handler for {{ stig_id }} has been selected for skip.''\n"'
    - stateful: True
    - cwd: /root
# Nothing's OS-level encrypted without LUKS packages...
{%- elif salt.pkg.version(corePkg) %}

  # Grab info about all active mounts and stuff into a searchable struct
  {%- set activeMntStream = salt.mount.active('extended=false') %}
  # Iterate the structure by top-level key
  {%- for mountPoint in activeMntStream.keys() %}
    # We don't care about pseudo-filesystems
    {%- if not ( 
               mountPoint.startswith('/sys') or 
               mountPoint.startswith('/dev') or
               mountPoint.startswith('/run') or
               mountPoint.startswith('/proc')
             ) %}
      # Unpack what's left
      {%- set mountList = activeMntStream[mountPoint] %}
      {%- set mountDev = mountList['device'] %}
check_{{ stig_id }}-{{ mountPoint }}:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}_helper.sh
    - name: '{{ helperLoc }}/{{ stig_id }}_helper.sh "{{ mountDev }}" "{{ mountPoint }}"'
    - cwd: /root
    - stateful: True
     {%- endif %}
  {%- endfor %}
{%- else %}
present_{{ stig_id }}-{{ corePkg }}:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''OS-level disk-encryption capability not present.''\n"'
    - cwd: /root
    - stateful: True
{%- endif %}
