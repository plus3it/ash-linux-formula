# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-51369
# Finding ID:	V-51369
# Version:	RHEL-06-000023
# Finding Level:	Low
#
#     The system must use a Linux Security Module configured to limit the 
#     privileges of system services. Setting the SELinux policy to 
#     "targeted" or a more specialized policy ensures the system will 
#     confine processes that are likely to be targeted for exploitation, 
#     such as network or system services.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

script_V51369-describe:
  cmd.script:
  - source: salt://STIGbyID/cat3/files/V51369.sh

{% set selConfig = '/etc/selinux/config' %}
{% set selLink = '/etc/sysconfig/selinux' %}
{% set selType = 'SELINUXTYPE' %}
{% set typeMode = 'targeted' %}

{% if not salt['file.is_link'](selLink) %}
symlink_V51369-selinxCfg:
  file.symlink:
    - name: {{ selLink }}
    - target: {{ selConfig }}
{% endif %}

{% if salt['file.search'](selConfig, '^' + selType + '=') %}
  {% if salt['file.search'](selConfig, '^' + selType + '=' + typeMode) %}
set_V51369-selType:
  cmd.run:
  - name: 'echo "The SELinux ''{{ selType }}'' parameter already set to ''{{ typeMode }}''"'
  {% else %}
set_V51369-selType:
  file.replace:
  - name: {{ selConfig }}
  - pattern: '^{{ selType }}=.*$'
  - repl: '{{ selType }}={{ typeMode }}'
  {% endif %}
{% else %}
set_V51369-selType:
  file.append:
  - name: {{ selConfig }}
  - text: '{{ selType }}={{ typeMode }}'
{% endif %}
