# STIG ID:	RHEL-07-020020
# Rule ID:	SV-86595r2_rule
# Vuln ID:	V-71971
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
{%- set stig_id = 'RHEL-07-020020' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set mapped_users = salt.cmd.shell('semanage login -ln').split('\n') %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set stig_role = 'user_u' %}
{%- set regUserGid = 1000 %}
{%- set staffUsers      = salt.pillar.get('ash-linux:lookup:sel_confine:staff_u', []) %}
{%- set sysadmUsers     = salt.pillar.get('ash-linux:lookup:sel_confine:sysadm_u', []) %}
{%- set unconfinedUsers = salt.pillar.get('ash-linux:lookup:sel_confine:unconfined_u', []) %}

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
{%- else %}
  {%- for userName in salt.user.list_users() %}
    {%- set userInfo = salt.user.info(userName) %}
    {%- if userInfo.gid >= regUserGid %}

# Assign Pillar-specified users to 'staff_u' SEL-role
      {%- if userName in staffUsers %}
Map {{ userName }} to staff_u:
  cmd.run:
    - name: 'semanage login {{ userName }} -a -s staff_u'
    - unless:
      - 'semanage login -ln | grep "{{ userName }} "'
      {%- endif %}

# Assign Pillar-specified users to 'sysadm_u' SEL-role
      {%- if userName in sysadmUsers %}
Map {{ userName }} to sysadm_u:
  cmd.run:
    - name: 'semanage login {{ userName }} -a -s sysadm_u'
    - unless:
      - 'semanage login -ln | grep "{{ userName }} "'
      {%- endif %}

# Assign Pillar-specified users to 'unconfined_u' SEL-role
      {%- if userName in unconfinedUsers %}
Map {{ userName }} to unconfined_u:
  cmd.run:
    - name: 'semanage login {{ userName }} -a -s unconfined_u'
    - unless:
      - 'semanage login -ln | grep "{{ userName }} "'
      {%- endif %}

# Assign remaining, non-system users to '{{ stig_role }}' SEL-role
      {%- if userName + ' ' not in mapped_users %}
Map {{ userName }} to user_u:
  cmd.run:
    - name: 'semanage login {{ userName }} -a -s {{ stig_role }} && echo "Set {{ userName }}''s role to {{ stig_role }}"'
      {%- endif %}
    - unless:
      - 'semanage login -ln | grep "{{ userName }} "'
    {%- endif %}
  {%- endfor %}

Set "__default__" SELinux user-mapping to "user_u":
  test.show_notification:
    - text: |
        This state is currently a NOOP.

        Per {{ stig_id }}, the `__default__` user-mapping *should* be set to
        `user_u`. However, doing this would cause users that authenticate to the
        host via many third-party authentication-services to not be able to
        execute the `sudo` command.  Because the many of the users of this
        formula are using third-party authentication-services, this handler will
        not implement the STIG recommended setting.

        For users lgging in via third-party authentication-service, it will be
        necessary for those users to specify the `-r unconfined_r` and
        `-t unconfined_t` when invoking `sudo`.

{%- endif %}
