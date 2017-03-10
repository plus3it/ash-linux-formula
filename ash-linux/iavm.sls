{%- set ver = grains['osmajorrelease'] %}
include:
  - ash-linux.stig
  - ash-linux.el{{ ver }}.SCAPonly
  - ash-linux.el{{ ver }}.Nessus
