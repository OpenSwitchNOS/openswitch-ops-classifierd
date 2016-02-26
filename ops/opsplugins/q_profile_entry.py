from opsvalidator.base import *
from opsvalidator import error
from opsvalidator.error import ValidationError
from opsrest.utils import *
from tornado.log import app_log

import qos_utils

class QProfileEntryValidator(BaseValidator):
    resource = "q_profile_entry"

    def validate_modification(self, validation_args):
        profile_row = validation_args.p_resource_row
        profile_entry_row = validation_args.resource_row

        self.validate_profile_applied_cannot_be_amended_or_deleted(validation_args, profile_row)
        self.validate_profile_entry_name_contains_valid_chars(profile_entry_row)
        self.validate_profile_entry_does_not_contain_duplicate_local_priorities(profile_entry_row, profile_row)

    def validate_deletion(self, validation_args):
        pass

    def validate_profile_applied_cannot_be_amended_or_deleted(self, validation_args, profile_row):
        if qos_utils.queue_profile_is_applied(validation_args, profile_row):
            details = "An applied profile cannot be amended or deleted."
            raise ValidationError(error.VERIFICATION_FAILED, details)

    def validate_profile_entry_name_contains_valid_chars(self, profile_entry_row):
        profile_entry_name = profile_entry_row.description[0]
        qos_utils.validate_string_contains_valid_chars(profile_entry_name)

    def validate_profile_entry_does_not_contain_duplicate_local_priorities(self, profile_entry_row, profile_row):
        all_local_priorities = []
        q_profile_entries = utils.get_column_data_from_row(profile_row, "q_profile_entries")
        for i_profile_entry_row in q_profile_entries.values():
            for local_priority in i_profile_entry_row.local_priorities:
                if local_priority in all_local_priorities:
                    details = "The profile cannot contain duplicate local priorities."
                    raise ValidationError(error.VERIFICATION_FAILED, details)
                else:
                    all_local_priorities.append(local_priority)
