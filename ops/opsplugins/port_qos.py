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
# REST Custom Validator for QoS for the Port table.
#
class PortQosValidator(BaseValidator):
    resource = "port"

    #
    # Validates that the given modification to a given row is allowed.
    #
    def validate_modification(self, validation_args):
        port_row = validation_args.resource_row

        idl = validation_args.idl
        system_row = ""
        for i in idl.tables["System"].rows.itervalues():
            system_row = i

        self.validate_port_override_has_port_trust_mode_none(
            port_row, qos_utils.QOS_COS_OVERRIDE_KEY, "COS")
        self.validate_port_override_has_port_trust_mode_none(
            port_row, qos_utils.QOS_DSCP_OVERRIDE_KEY, "DSCP")
        self.validate_apply_port_schedule_profile_has_same_algorithm_on_all_queues(
            port_row)
        self.validate_apply_port_queue_profile_contains_all_schedule_profile_queues(
            port_row, system_row)
        self.validate_apply_port_schedule_profile_contains_all_queue_profile_queues(
            port_row, system_row)

    #
    # Validates that the given deletion of a given row is allowed.
    #
    def validate_deletion(self, validation_args):
        pass

    #
    # Validates that port overrides are only allowed when the port trust
    # mode is 'none'.
    #
    def validate_port_override_has_port_trust_mode_none(self, port_row, qos_config_key, display_string):
        qos_config = utils.get_column_data_from_row(port_row, "qos_config")

        qos_override = qos_config.get(qos_config_key, None)
        if qos_override is None:
            return

        qos_trust_value = qos_config.get(qos_utils.QOS_TRUST_KEY, None)
        if qos_trust_value is None or qos_trust_value != qos_utils.QOS_TRUST_NONE_STRING:
            details = "QoS " + display_string + \
                " override is only allowed if the port trust mode is 'none'."
            raise ValidationError(error.VERIFICATION_FAILED, details)

    #
    # Validates that the port schedule profile has the same algorithm on
    # all queues.
    #
    def validate_apply_port_schedule_profile_has_same_algorithm_on_all_queues(self, port_row):
        schedule_profile = utils.get_column_data_from_row(port_row, "qos")
        if schedule_profile == []:
            return

        qos_utils.validate_schedule_profile_has_same_algorithm_on_all_queues(
            schedule_profile[0])

    #
    # Validates that the port queue profile contains all of the schedule
    # profile queues.
    #
    def validate_apply_port_queue_profile_contains_all_schedule_profile_queues(self, port_row, system_row):
        schedule_profile = utils.get_column_data_from_row(port_row, "qos")
        if schedule_profile == []:
            return

        queue_profile = utils.get_column_data_from_row(system_row, "q_profile")
        qos_utils.validate_queue_profile_contains_all_schedule_profile_queues(
            queue_profile[0], schedule_profile[0])

    #
    # Validates that the port schedule profile contains all of the queue
    # profile queues.
    #
    def validate_apply_port_schedule_profile_contains_all_queue_profile_queues(self, port_row, system_row):
        schedule_profile = utils.get_column_data_from_row(port_row, "qos")
        if schedule_profile == []:
            return

        queue_profile = utils.get_column_data_from_row(system_row, "q_profile")
        qos_utils.validate_schedule_profile_contains_all_queue_profile_queues(
            queue_profile[0], schedule_profile[0])
