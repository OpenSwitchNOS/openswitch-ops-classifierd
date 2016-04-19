{%- macro param_attrs(attrs) -%}
{% if attrs -%}
, {% for attr in attrs -%}
{{ attr.name|variablize }}
{%- if 'optional' in attr.keys() and attr.optional %}=''{% endif %}
{%- if not loop.last %}, {% endif -%}
{%- endfor %}
{%- endif %}
{%- endmacro -%}
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2016 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""
Vtysh auto-generated communication library module.

.. warning::

   This is auto-generated, do not modify manually!!
"""

from __future__ import unicode_literals, absolute_import
from __future__ import print_function, division

from .parser import *  # noqa
from .exceptions import determine_exception


class ContextManager(object):
    """
    This class defines a context manager object.

    Usage:

    ::

        with ClassName(parameters) as ctx:
            ctx.first_function()
            ctx.second_function()

    This way at the beginning the **pre_commands** will be run and at the end
    the **post_commands** will clean the vtysh terminal. Every implementation
    of this class document their pre_commands and post_commands.

    """

{% for context_name, context in spec.items() if context_name != 'root' %}
class {{ context_name|objectize }}(ContextManager):
    """
    {{ context.doc|wordwrap(75)|indent(4) }}

    pre_commands:

    ::

            {{ context.pre_commands }}

    post_commands:

    ::

            {{ context.post_commands }}
    """
    def __init__({{ 'self, enode%s):'|format(param_attrs(context.arguments))|wordwrap(67)|indent(12) }}
        self.enode = enode
        {%- for arg in context.arguments %}
        {% if arg.name == 'portlbl' -%}
        self.port = enode.ports.get(portlbl, portlbl)
        {%- else -%}
        self.{{ arg.name }} = {{ arg.name }}
        {%- endif %}
        {%- endfor %}

    def __enter__(self):
        commands = """\
        {%- for pre_command in context.pre_commands %}
            {{ pre_command }}
        {%- endfor %}
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

        return self

    def __exit__(self, type, value, traceback):
        commands = """\
        {%- for post_command in context.post_commands %}
            {{ post_command }}
        {%- endfor %}
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )
{% for command in context.commands %}
    def {{ command.command|methodize }}(
            {{ 'self%s):'|format(param_attrs(command.arguments))|wordwrap(56)|indent(12) }}
        """
        {{ command.doc|wordwrap(71)|indent(8) }}

        This function runs the following vtysh command:

        ::

            # {{ command.command }}{% if command.command|length > 65%}  # noqa{% endif %}

        {% for attr in command.arguments -%}
        {{ ':param %s: %s'|format(attr.name, attr.doc)|wordwrap(70)|indent(12) }}
        {% endfor -%}
        {%- if 'returns' in command.keys() and command.returns -%}
        :return: A dictionary as returned by
         :func:`topology_lib_vtysh.parser.{{ 'parse_%s'|format(command.command|methodize) }}`
        {% endif -%}
        """{% if command.command|length > 66%}  # noqa{% endif %}
        {%- for attr in command.arguments -%}
            {% if attr.name == 'portlbl' %}
        port = self.enode.ports.get(portlbl, portlbl)
            {%- endif -%}
        {%- endfor %}

        cmd = (
            '{{ command.command|wordwrap(64, wrapstring=" \'\n\'")|indent(12)}}'
        )
        result = self.enode(cmd.format(**locals()), shell='vtysh')

        {% if 'returns' in command.keys() and command.returns -%}
        {{ 'return parse_%s(result)'|format(command.command|methodize) }}
        {%- else -%}
        if result:
            raise determine_exception(result)(result)
        {%- endif %}
{% endfor %}
{% endfor -%}

{% for command in spec.root.commands %}
def {{ command.command|methodize }}(
        {{'enode%s):'|format(param_attrs(command.arguments))|wordwrap(67)|indent(8) }}
    """
    {{ command.doc|wordwrap(71)|indent(4) }}

    This function runs the following vtysh command:

    ::

        # {{ command.command }}{% if command.command|length > 68%}  # noqa{% endif %}

    {% for attr in command.arguments -%}
    {{ ':param %s: %s'|format(attr.name, attr.doc)|wordwrap(75)|indent(5) }}
    {% endfor -%}
    {%- if 'returns' in command.keys() and command.returns -%}
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.{{ 'parse_%s'|format(command.command|methodize) }}`
    {% endif -%}
    """{% if command.command|length > 69%}  # noqa{% endif %}
    {%- for attr in command.arguments -%}
        {% if attr.name == 'portlbl' %}
    port = enode.ports.get(portlbl, portlbl)
        {%- endif -%}
    {%- endfor %}

    cmd = (
        '{{ command.command|wordwrap(67, wrapstring=" \'\n\'")|indent(8)}}'
    )
    result = enode(cmd.format(**locals()), shell='vtysh')

    {% if 'returns' in command.keys() and command.returns -%}
    {{ 'return parse_%s(result)'|format(command.command|methodize) }}
    {%- else -%}
    if result:
        raise determine_exception(result)(result)
    {%- endif %}

{% endfor %}
__all__ = [
    'ContextManager',
{%- for context_name in spec.keys() if context_name != 'root' %}
    '{{ context_name|objectize }}',
{%- endfor %}
{%- for function in spec.root.commands %}
    '{{ function.command|methodize }}'{% if not loop.last %},{% endif %}
{%- endfor %}
]
{# #}
