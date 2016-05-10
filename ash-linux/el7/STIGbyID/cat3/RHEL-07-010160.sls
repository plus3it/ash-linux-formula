# STIG URL:
# Finding ID:	RHEL-07-010160
# Version:	RHEL-07-010160_rule
# SRG ID:	SRG-OS-000072-GPOS-0040
# Finding Level:	low
#
# Rule Summary:
#     When passwords are changed the number of repeating characters of 
#     the same character class must not be more than two characters.
#
# CCI-000195
#    NIST SP 800-53 :: IA-5 (1) (b)
#    NIST SP 800-53A :: IA-5 (1).1 (v)
#    NIST SP 800-53 Revision 4 :: IA-5 (1) (b)
#
#################################################################
{%- set stig_id = 'RHEL-07-010160' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat3/files' %}
{%- set chkFile = '/etc/security/pwquality.conf' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- if salt['file.contains'](chkFile, '# maxrepeat') %}
uncomment_{{ stig_id }}-{{ chkFile }}:
  file.replace:
    - name: '{{ chkFile }}'
    - pattern: '^# maxclassrepeat.*$'
    - repl: 'maxclassrepeat = 2'
{%- else %}
setval_{{ stig_id }}-{{ chkFile }}:
  file.replace:
    - name: '{{ chkFile }}'
    - pattern: '^maxclassrepeat.*$'
    - repl: 'maxclassrepeat = 2'
    - append_if_not_found: True
{%- endif %}
