script_GEN000560:
  cmd.script:
  - source: salt://cat1/files/gen000560.sh

file_GEN001400_shadow:
  file.managed:
  - name: /etc/shadow
  - user: root
  - group: root
  - mode: 0000

file_GEN001400_passwd:
  file.managed:
  - name: /etc/passwd
  - user: root
  - group: root
  - mode: 0644

