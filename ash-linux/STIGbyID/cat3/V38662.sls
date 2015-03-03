# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38662
# Finding ID:	V-38662
# Version:	RHEL-06-000277
# Finding Level:	Low
#
#     The operating system must employ cryptographic mechanisms to prevent 
#     unauthorized disclosure of data at rest unless otherwise protected by 
#     alternative physical measures. The risk of a system's physical 
#     compromise, particularly mobile systems such as laptops, places its 
#     data at risk of compromise. Encrypting this data mitigates the risk 
#     of its loss if the system is lost.
#
#  CCI: CCI-001200
#  NIST SP 800-53 :: SC-28 (1)
#  NIST SP 800-53A :: SC-28 (1).1 (i)
#
############################################################

script_V38662-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat3/files/V38662.sh
    - cwd: /root

notify_V38662-NotApplicable:
  cmd.run:
    - name: 'printf "Not a technical control:\n\tReview local policies then determine\n\tif policies have been applied to system.\n\tModule will check for LUKS indicators.\n"'

{% if salt['file.file_exists']('/etc/crypttab') %}
notify_V38662-CryptTab:
  cmd.run:
    - name: 'echo "System crypttab found."'

chk_V38662-LUKSdevs:
  cmd.run:
    - name: "echo 'Found LUKS-devs:' ; blkid -t TYPE=ext4 | awk -F':' '{print $1}'"
{% else %}
notify_V38662-CryptTab:
  cmd.run:
    - name: 'echo "No crypttab file found: automated LUKS mounts not configured."'
  {% if not salt['pkg.version']('cryptsetup-luks') %}
notify_V38662-LUKStools:
  cmd.run:
    - name: 'echo "LUKS tools not installed: LUKS device-management not possible."'
  {% endif %}
{% endif %}
