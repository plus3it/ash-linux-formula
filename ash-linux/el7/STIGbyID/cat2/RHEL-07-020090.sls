# Finding ID:	RHEL-07-020090
# Version:	RHEL-07-020090_rule
# SRG ID:	SRG-OS-000324-GPOS-00125
# Finding Level:	medium
# 
# Rule Summary:
#	The operating system must prevent non-privileged users from
#	executing privileged functions to include disabling,
#	circumventing, or altering implemented security
#	safeguards/countermeasures.
#
# CCI-002165 
# CCI-002235 
#    NIST SP 800-53 Revision 4 :: AC-3 (4) 
#    NIST SP 800-53 Revision 4 :: AC-6 (10) 
#
#################################################################
{%- set stig_id = 'RHEL-07-020090' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set stig_role = 'user_u' %}
{%- set regUserGid = 1000 %}
{%- set admUsers = [] %}
{%- set stfUsers = [] %}
{%- set uncUsers = [] %}
{%- set nulUsers = [] %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- for userName in salt.user.list_users() %}
{%- set userInfo = salt.user.info(userName) %}
  {%- if userInfo.gid >= regUserGid %}
    {%- set seUmap =  salt['cmd.shell']('semanage login -ln | awk \'/' + userName + '/{print $2}\'') %}
    {%- if seUmap == "unconfined_u" %}
      {%- do uncUsers.append(userName) %}
    {%- elif seUmap == "staff_u" %}
      {%- do stfUsers.append(userName) %}
    {%- elif seUmap == "sysadm_u" %}
      {%- do admUsers.append(userName) %}
    {%- elif seUmap == "" %}
      {%- do nulUsers.append(userName) %}
    {%- endif %}
  {%- endif %}
{%- endfor %}

{%- if nulUsers %}
  {%- for nullUser in nulUsers %}
set_{{ stig_id }}-SELuserRole-{{ nullUser }}:
  cmd.run:
    - name: 'semanage login {{ nullUser }} -a -s {{ stig_role }} && echo "Set {{ nullUser }}''s role to {{ stig_role }}"'
    - cwd: /root

  {%- endfor %}
{%- endif %} 

{%- if not salt['cmd.shell']('semanage login -l | awk \'/^__defaul/{ print $2}\'') == stig_role %}
notify_{{ stig_id }}-baDefault:
  cmd.run:
    - name: 'printf "[WARNING] Default SEL login user role-mapping is not\n\t\"{{ stig_role }}\": users created after this state runs will\n\tneed to be explicitly set to STIG-compatible roles."'
    - cwd: /root

{%- endif %} 
