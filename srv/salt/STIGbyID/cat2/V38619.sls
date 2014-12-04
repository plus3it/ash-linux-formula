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
############################################################

script_V38619-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38619.sh

{% for user in salt['user.getent']('') %}
  {% set ID = user['name'] %}
  {% set homeDir = user['home'] %}
  {% set netRc = homeDir + '/.netrc' %}

  {% if salt['file.file_exists'](netRc) %}
notify_V38619-{{ ID }}:
  cmd.run:
  - name: 'echo "Found netrc file at: ''{{ netRc }}''. Moving..."'

move_V38619-{{ ID }}:
  file.rename:
  - src: '{{ netRc }}'
  - dst: '{{ netRc }}-MOVEDperSTIGS'

warn_V38619-{{ ID }}:
  file.prepend
  - name: '{{ netRc }}-MOVEDperSTIGS'
  - onlyif: 'move_V38619-{{ ID }}'
  - text:
    - '######################################################'
    - '# This file moved in accordance with STIG-ID V-38619'
    - '#'
    - '# DO NOT RENAME TO ''{{ homeDir}}/.netrc'' '
    - '#'
    - '######################################################'

  {% endif %}
{% endfor %}

