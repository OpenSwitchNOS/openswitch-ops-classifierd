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
Vtysh auto-generated typed exceptions module.

.. warning::

   This is auto-generated, do not modify manually!!
"""

from __future__ import unicode_literals, absolute_import
from __future__ import print_function, division

# from re import match VM
from re import search
from re import sub
from collections import OrderedDict


class VtyshException(Exception):
    """
    Base exception class for vtysh shell errors.

    :param str output: The shell output that triggered this exception.
    """
    def __init__(self, output):
        super(VtyshException, self).__init__()
        self.output = output


class UnknownVtyshException(VtyshException):
    """
    Generic exception raised when the specific exception could not be
    determined.
    """


class UnknownCommandException(VtyshException):
    """
    This is a typed exception that will be raised when any of the following
    regular expressions match the output of a command:

    ::
        unknown command

    """


class IncompleteCommandException(VtyshException):
    """
    This is a typed exception that will be raised when any of the following
    regular expressions match the output of a command:

    ::
        command incomplete

    """


class InvalidQnCommandException(VtyshException):
    """
    This is a typed exception that will be raised when any of the following
    regular expressions match the output of a command:

    ::
        name  acl name

    """


class AclEmptyException(VtyshException):
    """
    This is a typed exception that will be raised when any of the following
    regular expressions match the output of a command:

    ::
        acl is empty

    """


class TcamResourcesException(VtyshException):
    """
    This is a typed exception that will be raised when any of the following
    regular expressions match the output of a command:

    ::
        command failed

    """


class ResequenceNumberException(VtyshException):
    """
    This is a typed exception that will be raised when any of the following
    regular expressions match the output of a command:

    ::
        sequence numbers would exceed maximum

    """


class AmbiguousCommandException(VtyshException):
    """
    This is a typed exception that will be raised when any of the following
    regular expressions match the output of a command:

    ::
        ambiguous command

    """


class InvalidL4SourcePortRangeException(VtyshException):
    """
    This is a typed exception that will be raised when any of the following
    regular expressions match the output of a command:

    ::
        invalid l4 source port range

    """


class EchoCommandException(VtyshException):
    """
    This is a typed exception that will be raised when any of the following
    regular expressions match the output of a command:

    ::
        range

    """


class AceDoesNotExistException(VtyshException):
    """
    This is a typed exception that will be raised when any of the following
    regular expressions match the output of a command:

    ::
        acl entry does not exist

    """


class AclDoesNotExistException(VtyshException):
    """
    This is a typed exception that will be raised when any of the following
    regular expressions match the output of a command:

    ::
        acl does not exist

    """


VTYSH_EXCEPTIONS = OrderedDict([
    (
        UnknownCommandException,
        [
            'unknown command',
        ]
    ),
    (
        IncompleteCommandException,
        [
            'command incomplete',
        ]
    ),
    (
        InvalidQnCommandException,
        [
            'name  acl name',
        ]
    ),
    (
        AclEmptyException,
        [
            'acl is empty',
        ]
    ),
    (
        TcamResourcesException,
        [
            'command failed',
        ]
    ),
    (
        ResequenceNumberException,
        [
            'sequence numbers would exceed maximum',
        ]
    ),
    (
        AmbiguousCommandException,
        [
            'ambiguous command',
        ]
    ),
    (
        InvalidL4SourcePortRangeException,
        [
            'invalid l4 source port range',
        ]
    ),
    (
        EchoCommandException,
        [
            'range',
        ]
    ),
    (
        AceDoesNotExistException,
        [
            'acl entry does not exist',
        ]
    ),
    (
        AclDoesNotExistException,
        [
            'acl does not exist',
        ]
    ),
])


def determine_exception(output):
    """
    Determine which exception to raise from shell error message.

    :param str output: The shell output error.
    :rtype: VtyshException subclass.
    :return: The corresponding exception class for given message.
    """
    output = sub('[%]+', '', output)
    output = output.strip().lower()
    for exc, matches in VTYSH_EXCEPTIONS.items():
        for expression in matches:
            if search(expression, output):
                return exc
    return UnknownVtyshException


__all__ = [
    'VtyshException',
    'UnknownVtyshException',
    'UnknownCommandException',
    'IncompleteCommandException',
    'InvalidQnCommandException',
    'AclEmptyException',
    'TcamResourcesException',
    'ResequenceNumberException',
    'AmbiguousCommandException',
    'InvalidL4SourcePortRangeException',
    'EchoCommandException',
    'AceDoesNotExistException',
    'AclDoesNotExistException',
    'VTYSH_EXCEPTIONS',
    'determine_exception'
]
