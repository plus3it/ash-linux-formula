{% from "ash-linux/fix_perms/0750_mode.jinja" import mode_0750_files with context %}

{% for filename in mode_0750_files %}
  {% if salt['file.file_exists'](filename) %}
{{ filename }}:
  file.directory:
    - mode: 0750
  {% endif %}
{% endfor %}
