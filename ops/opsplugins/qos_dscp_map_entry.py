from opsvalidator.base import *
from opsvalidator import error
from opsvalidator.error import ValidationError
from opsrest.utils import *
from tornado.log import app_log

import qos_utils

class QosDscpMapEntryValidator(BaseValidator):
    resource = "qos_dscp_map_entry"

    def validate_modification(self, validation_args):
        qos_dscp_map_entry_row = validation_args.resource_row
        self.validate_dscp_map_description_contains_valid_chars(qos_dscp_map_entry_row)

    def validate_deletion(self, validation_args):
        details = "DSCP Map Entries cannot be deleted"
        raise ValidationError(error.VERIFICATION_FAILED, details)

    def validate_dscp_map_description_contains_valid_chars(self, qos_dscp_map_entry_row):
        description = qos_dscp_map_entry_row.description[0]
        qos_utils.validate_string_contains_valid_chars(description)
