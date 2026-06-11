# -*- coding: utf-8 -*-
# vim: ft=yaml
#
# This Salt state creates a tier-80 exception in fapolicyd for the AWS CLI v2.

{%- set rules_dir = '/etc/fapolicyd/rules.d' %}
{%- set target_file = rules_dir ~ '/80-aws.rules' %}
{%- set search_pattern = '/usr/local/aws-cli/v2' %}
{%- set match_files = [] %}
{%- set baseline_rules = [
      'allow perm=any all : path=/usr/local/bin/aws',
      'allow perm=any all : dir=/usr/local/aws-cli/v2/',
      'allow perm=any comm=aws : dir=/var/tmp/'
    ]
%}

{%- set aggregated_rules = [] %}
{%- for baseline_rule in baseline_rules %}
  {%- do aggregated_rules.append(baseline_rule) %}
{%- endfor %}

{%- if salt['file.directory_exists'](rules_dir) %}
  {%- set found_files = salt['file.find'](
        rules_dir,
        grep=search_pattern,
        type='f'
      )
  %}
  {%- for file_path in found_files %}
    {%- if file_path != target_file %}
      {%- if salt['file.file_exists'](file_path) %}
        {%- do match_files.append(file_path) %}
        {%- set file_content = salt['file.read'](file_path) %}
        {%- if file_content %}
          {%- for line in file_content.splitlines() %}
            {%- set cleaned_rule = line.strip() %}
            {%- if (
                cleaned_rule
                and cleaned_rule not in aggregated_rules
            ) %}
              {%- do aggregated_rules.append(cleaned_rule) %}
            {%- endif %}
          {%- endfor %}
        {%- endif %}
      {%- endif %}
    {%- endif %}
  {%- endfor %}
{%- endif %}
{%- set sorted_match_files = match_files | sort %}

Aggregate And Specify AWS Rules:
  file.managed:
    - contents: |
        {%- for rule_entry in aggregated_rules %}
        {{ rule_entry }}
        {%- endfor %}
    - group: fapolicyd
    - mode: '0644'
    - name: '{{ target_file }}'
    - user: root

Ensure Fapolicyd Service Operational:
  service.running:
    - name: fapolicyd
    - reload: False
    - watch:
        - cmd: 'Reload Fapolicyd Policy'

{%- for old_file in sorted_match_files %}
Purge Obsoleted Rule File - {{ old_file }}:
  file.absent:
    - name: '{{ old_file }}'
    - require:
        - file: 'Aggregate And Specify AWS Rules'
    - require_in:
        - cmd: 'Reload Fapolicyd Policy"
{%- endfor %}

Reload Fapolicyd Policy:
  cmd.run:
    - name: fagenrules --load
    - onchanges:
        - file: 'Aggregate And Specify AWS Rules'
