{%- set ver = grains['osmajorrelease'] %}
include:
  - ash-linux.el{{ ver }}.SCAPonly
