# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38619
# Finding ID:	V-38619
# Version:	RHEL-06-000347
# Finding Level:	Medium
#
#     There must be no .netrc files on the system. Unencrypted passwords
#     for remote FTP servers may be stored in ".netrc" files. DoD policy
#     requires passwords be encrypted in storage and not used in access
#     scripts.
#
#  CCI: CCI-000196
#  NIST SP 800-53 :: IA-5 (1) ©
#  NIST SP 800-53A :: IA-5 (1).1 (v)
#  NIST SP 800-53 Revision 4 :: IA-5 (1)
#
############################################################

{%- set stigId = 'V38619' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

{%- for user in salt.ash.shadow_list_users() %}
  {%- set userinfo = salt.user.info(user) %}
  {%- set ID = userinfo['name'] %}
  {%- set homeDir = userinfo['home'] %}
  {%- set netRc = homeDir + '/.netrc' %}

  {%- if salt.file.file_exists(netRc) %}
notify_{{ stigId }}-{{ ID }}:
  cmd.run:
    - name: 'echo "Found netrc file at: ''{{ netRc }}''. Moving..."'

move_{{ stigId }}-{{ ID }}:
  file.rename:
    - source: '{{ netRc }}'
    - name: '{{ netRc }}-MOVEDperSTIGS'

warnfile_{{ stigId }}-{{ ID }}:
  file.prepend:
    - name: '{{ netRc }}-MOVEDperSTIGS'
    - text: |
        ##################################################
        # File moved per STIG {{ stigId }}
        #
        # DO NOT RENAME to {{ netRc }}
        # * presence of netrcs is a security-violation
        #
        ##################################################

{%- endif %}
{%- endfor %}
