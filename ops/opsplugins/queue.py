from opsvalidator.base import *
from opsvalidator import error
from opsvalidator.error import ValidationError
from opsrest.utils import *
from tornado.log import app_log

import qos_utils

class QueueValidator(BaseValidator):
    resource = "queue"

    def validate_modification(self, validation_args):
        profile_row = validation_args.p_resource_row
        profile_entry_row = validation_args.resource_row

        self.validate_profile_applied_cannot_be_amended_or_deleted(validation_args, profile_row)
        self.validate_profile_entry_with_wrr_must_have_weight(profile_entry_row)

    def validate_deletion(self, validation_args):
        pass

    def validate_profile_applied_cannot_be_amended_or_deleted(self, validation_args, profile_row):
        if qos_utils.schedule_profile_is_applied(validation_args, profile_row):
            details = "An applied profile cannot be amended or deleted."
            raise ValidationError(error.VERIFICATION_FAILED, details)

    def validate_profile_entry_with_wrr_must_have_weight(self, profile_entry_row):
        if profile_entry_row.algorithm[0] == qos_utils.QOS_WRR and not profile_entry_row.weight:
            details = "A wrr profile entry must have a weight."
            raise ValidationError(error.VERIFICATION_FAILED, details)
