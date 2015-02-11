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

# Possible applicable SELinux modes are determined by the installed 
# SELinux policy-support modules. As of the writing of this 
# enforcement-utility, the following pre-packaged policy modules are 
# available for Enterprise Linux 6:
#    'minimum' policy moudules:			selinux-policy-minimum
#    'multi-level security' policy modules:	selinux-policy-mls
#    'targeted' policy modules:			selinux-policy-targeted
# The STIGs specify a minum level of "targeted"; however the 
# more-restrictive 'mls' level may be substituted if the associated 
# policy modules are installed.

script_V51369-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat3/files/V51369.sh

{% set selConfig = '/etc/selinux/config' %}
{% set selLink = '/etc/sysconfig/selinux' %}
{% set selType = 'SELINUXTYPE' %}

# Set SELINUXTYPE based on highest, installed policy-set
{% if salt['pkg.version']('selinux-policy-mls') %}
  {% set typeMode = 'mls' %}
notify_V51369-selWarn:
  cmd.run:
    - name: 'printf "STIG only mandates ''targeted''\n   mode. Setting ''mls'' due to \n  presence of the associated policy-\n  modules. This may break many\n   things if ''SELINUX=enforcing''\n"'
{% elif salt['pkg.version']('selinux-policy-targeted') %}
  {% set typeMode = 'targeted' %}
{% else %}
notify_V51369-selWarn:
  cmd.run:
    - name: 'printf "STIG-compatible policy-modules not\n  installed. Install before\n  rebooting or system may fail\n  to properly restart."'
{% endif %}

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

touch_V51369-relabel:
  file.touch:
    - name: '/.autorelabel'
  {% endif %}
{% else %}
set_V51369-selType:
  file.append:
    - name: {{ selConfig }}
    - text: '{{ selType }}={{ typeMode }}'

touch_V51369-relabel:
  file.touch:
    - name: '/.autorelabel'
{% endif %}
