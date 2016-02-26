from opsvalidator.base import *
from opsvalidator import error
from opsvalidator.error import ValidationError
from opsrest.utils import *
from tornado.log import app_log

import qos_utils

class SystemQosValidator(BaseValidator):
    resource = "system"

    def validate_modification(self, validation_args):
        system_row = validation_args.resource_row
        self.validate_trust_global_is_not_empty(system_row)
        self.validate_apply_global_queue_profile_has_all_local_priorities(system_row)
        self.validate_apply_global_schedule_profile_has_same_algorithm_on_all_queues(system_row)
        self.validate_apply_global_queue_profile_contains_all_schedule_profile_queues(system_row)
        self.validate_apply_global_schedule_profile_contains_all_queue_profile_queues(system_row)

    def validate_deletion(self, validation_args):
        pass

    def validate_trust_global_is_not_empty(self, system_row):
        qos_config = utils.get_column_data_from_row(system_row, "qos_config")
        qos_trust_value = qos_config.get(qos_utils.QOS_TRUST_KEY, None)
        if qos_trust_value is None:
            details = "The qos trust value cannot be empty."
            raise ValidationError(error.VERIFICATION_FAILED, details)

    def validate_apply_global_queue_profile_has_all_local_priorities(self, system_row):
        q_profile = utils.get_column_data_from_row(system_row, "q_profile")

        if q_profile is not None:
            for local_priority in range(0, qos_utils.QOS_MAX_LOCAL_PRIORITY):
                if not self.profile_has_local_priority(q_profile[0], local_priority):
                    details = "The queue profile must have each local priority assigned to a queue."
                    raise ValidationError(error.VERIFICATION_FAILED, details)

    def profile_has_local_priority(self, q_profile, local_priority):
        q_profile_entries = utils.get_column_data_from_row(
            q_profile, "q_profile_entries")
        for q_profile_entry in q_profile_entries.values():
            if self.queue_has_local_priority(q_profile_entry, local_priority):
                return True

        return False

    def queue_has_local_priority(self, q_profile_entry, local_priority):
        local_priorities = utils.get_column_data_from_row(
            q_profile_entry, "local_priorities")
        for local_priority_from_row in local_priorities:
            if local_priority_from_row == local_priority:
                return True

        return False

    def validate_apply_global_schedule_profile_has_same_algorithm_on_all_queues(self, system_row):
        schedule_profile = utils.get_column_data_from_row(system_row, "qos")
        qos_utils.validate_schedule_profile_has_same_algorithm_on_all_queues(schedule_profile[0])

    def validate_apply_global_queue_profile_contains_all_schedule_profile_queues(self, system_row):
        q_profile = utils.get_column_data_from_row(system_row, "q_profile")
        schedule_profile = utils.get_column_data_from_row(system_row, "qos")
        qos_utils.validate_queue_profile_contains_all_schedule_profile_queues(q_profile[0], schedule_profile[0])

    def validate_apply_global_schedule_profile_contains_all_queue_profile_queues(self, system_row):
        q_profile = utils.get_column_data_from_row(system_row, "q_profile")
        schedule_profile = utils.get_column_data_from_row(system_row, "qos")
        qos_utils.validate_schedule_profile_contains_all_queue_profile_queues(q_profile[0], schedule_profile[0])
