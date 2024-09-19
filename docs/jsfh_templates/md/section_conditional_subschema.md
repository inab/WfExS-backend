{% if schema.kw_if %}
    {% set first_property =  schema.kw_if | get_first_property %}

    {% if schema.kw_then %}
        {% if first_property is not none %}
            {%- filter md_heading(depth) -%}If (
                {{- first_property.property_name | md_escape_for_table -}}
                {{- " = " -}}
                {% if first_property.kw_const is not none %}
                    {{- first_property.kw_const.literal | python_to_json -}}
                {% elif first_property.kw_enum is not none %}
                    {% with schema=first_property %}
                        {% include "section_one_of.md" %}
                    {% endwith %}
                {% else %}
                    {{- "(unimplemented rendering)" -}}
                {% endif %}
            ){%- endfilter -%}
        {% else %}
            If(_complex condition_)
        {% endif %}
        {% with schema=schema.kw_then, skip_headers=False, depth=depth %}
            {% include "content.md" %}
        {% endwith %}
    {% endif %}
    {% if schema.kw_else %}
        {% if first_property is not none %}
            {%- filter md_heading(depth) -%}Else (i.e. {{ " " }}
                {{- first_property.property_name | md_escape_for_table -}}
                {{- " != " -}}
                {% if first_property.kw_const is not none %}
                    {{- first_property.kw_const.literal | python_to_json -}}
                {% elif first_property.kw_enum is not none %}
                    {% with schema=first_property %}
                        {% include "section_one_of.md" %}
                    {% endwith %}
                {% else %}
                    {{- "(unimplemented rendering)" -}}
                {% endif %}
            ){%- endfilter -%}
        {% else %}
            IfNot(_complex condition_)
        {% endif %}
        {% with schema=schema.kw_else, skip_headers=False, depth=depth %}
            {% include "content.md" %}
        {% endwith %}
    {% endif %}
{% endif %}