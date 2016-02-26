from opsvalidator.base import *
from opsvalidator import error
from opsvalidator.error import ValidationError
from opsrest.utils import *
from tornado.log import app_log

import qos_utils

class QosValidator(BaseValidator):
    resource = "qos"

    def validate_modification(self, validation_args):
        profile_row = validation_args.resource_row
        self.validate_profile_applied_cannot_be_amended_or_deleted(validation_args, profile_row)
        self.validate_profile_name_contains_valid_chars(profile_row)
        self.validate_profile_name_cannot_be_strict(profile_row)

    def validate_deletion(self, validation_args):
        profile_row = validation_args.resource_row
        self.validate_profile_applied_cannot_be_amended_or_deleted(validation_args, profile_row)

    def validate_profile_applied_cannot_be_amended_or_deleted(self, validation_args, profile_row):
        if qos_utils.schedule_profile_is_applied(validation_args, profile_row):
            details = "An applied profile cannot be amended or deleted."
            raise ValidationError(error.VERIFICATION_FAILED, details)

    def validate_profile_name_contains_valid_chars(self, profile_row):
        profile_name = profile_row.name
        qos_utils.validate_string_contains_valid_chars(profile_name)

    def validate_profile_name_cannot_be_strict(self, profile_row):
        profile_name = profile_row.name
        if profile_name == qos_utils.QOS_STRICT:
            details = "The profile name cannot be '" + qos_utils.QOS_STRICT + "'."
            raise ValidationError(error.VERIFICATION_FAILED, details)
