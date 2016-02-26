#!/usr/bin/env python
# Copyright (C) 2015-2016 Hewlett Packard Enterprise Development LP
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from opsvalidator.base import *
from opsvalidator import error
from opsvalidator.error import ValidationError
from opsrest.utils import *
from tornado.log import app_log

import qos_utils

#
# REST Custom Validator for QoS for the Q Profile Entry table.
#
class QProfileEntryValidator(BaseValidator):
    resource = "q_profile_entry"

    #
    # Validates that the given modification to a given row is allowed.
    #
    def validate_modification(self, validation_args):
        profile_row = validation_args.p_resource_row
        profile_entry_row = validation_args.resource_row

        self.validate_profile_applied_cannot_be_amended_or_deleted(
            validation_args, profile_row)
        self.validate_profile_entry_name_contains_valid_chars(
            profile_entry_row)
        self.validate_profile_entry_does_not_contain_duplicate_local_priorities(
            profile_entry_row, profile_row)

    #
    # Validates that the given deletion of a given row is allowed.
    #
    def validate_deletion(self, validation_args):
        pass

    #
    # Validates that an applied profile cannot be amended or deleted.
    #
    def validate_profile_applied_cannot_be_amended_or_deleted(self, validation_args, profile_row):
        if qos_utils.queue_profile_is_applied(validation_args, profile_row):
            details = "An applied profile cannot be amended or deleted."
            raise ValidationError(error.VERIFICATION_FAILED, details)

    #
    # Validates that a profile entry name contains all valid characters.
    #
    def validate_profile_entry_name_contains_valid_chars(self, profile_entry_row):
        profile_entry_name = profile_entry_row.description[0]
        qos_utils.validate_string_contains_valid_chars(profile_entry_name)

    #
    # Validates that a profile entry does not contain any duplicate
    # local priorities.
    #
    def validate_profile_entry_does_not_contain_duplicate_local_priorities(self, profile_entry_row, profile_row):
        all_local_priorities = []
        q_profile_entries = utils.get_column_data_from_row(
            profile_row, "q_profile_entries")
        for i_profile_entry_row in q_profile_entries.values():
            for local_priority in i_profile_entry_row.local_priorities:
                if local_priority in all_local_priorities:
                    details = "The profile cannot contain duplicate local priorities."
                    raise ValidationError(error.VERIFICATION_FAILED, details)
                else:
                    all_local_priorities.append(local_priority)
