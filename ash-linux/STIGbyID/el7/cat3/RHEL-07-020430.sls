# STIG URL:
# Finding ID:	RHEL-07-020430
# Version:	RHEL-07-020430_rule
# SRG ID:	
# Finding Level:	low
#
# Rule Summary:
#     Manual page files must have mode 0644 or less permissive.
#
# CCI-000366
#    NIST SP 800-53 :: CM-6 b
#    NIST SP 800-53A :: CM-6.1 (iv)
#    NIST SP 800-53 Revision 4 :: CM-6 b
#
#################################################################
{%- set stig_id = 'RHEL-07-020430' %}
{%- set helperLoc = 'ash-linux/STIGbyID/el7/cat3/files' %}
{%- set dirList = [
        '/usr/share/man', 
        '/usr/share/info'
    ]
%}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- for dirChk in dirList %}
fixPerm_{{ stig_id }}-{{ dirChk }}:
  cmd.script:
    - name: '{{ stig_id }}-check_fix.sh "{{ dirChk }}"'
    - source: 'salt://{{ helperLoc }}/{{ stig_id }}-check_fix.sh'
    - cwd: '/root'
    - stateful: True
    - require:
      - cmd: script_{{ stig_id }}-describe
{%- endfor %}
