from opsvalidator.base import *
from opsvalidator import error
from opsvalidator.error import ValidationError
from opsrest.utils import *
from tornado.log import app_log

QOS_FACTORY_DEFAULT_NAME = "factory-default"
QOS_DEFAULT_NAME = "default"

QOS_TRUST_KEY = "qos_trust"
QOS_TRUST_NONE_STRING = "none"
QOS_TRUST_DEFAULT = QOS_TRUST_NONE_STRING

QOS_COS_OVERRIDE_KEY = "cos_override"
QOS_DSCP_OVERRIDE_KEY = "dscp_override"

QOS_LOCAL_PRIORITY_DEFAULT = 0
QOS_COLOR_DEFAULT = "green"
QOS_DESCRIPTION_DEFAULT = ""

QOS_STRICT = "strict"
QOS_WRR = "wrr"

QOS_MAX_LOCAL_PRIORITY = 7

QOS_COS_MAP_ENTRY_COUNT = 8

QOS_DSCP_MAP_ENTRY_COUNT = 64

def validate_string_contains_valid_chars(string):
    for c in string:
        if not is_valid_char(c):
            details = "The allowed characters are alphanumeric, underscore ('_'), and hyphen ('-')."
            raise ValidationError(error.VERIFICATION_FAILED, details)

def is_valid_char(c):
    return c.isalnum() or c == "_" or c == "-"

def queue_profile_is_applied(validation_args, queue_profile_row):
    idl = validation_args.idl

    for system_row in idl.tables["System"].rows.itervalues():
        if system_row.q_profile[0] == queue_profile_row:
            return True

    for port_row in idl.tables["Port"].rows.itervalues():
        if len(port_row.q_profile) != 0 and port_row.q_profile[0] == queue_profile_row:
            return True

    return False

def schedule_profile_is_applied(validation_args, schedule_profile_row):
    idl = validation_args.idl

    for system_row in idl.tables["System"].rows.itervalues():
        if system_row.qos[0] == schedule_profile_row:
            return True

    for port_row in idl.tables["Port"].rows.itervalues():
        if len(port_row.qos) != 0 and port_row.qos[0] == schedule_profile_row:
            return True

    return False

def validate_schedule_profile_has_same_algorithm_on_all_queues(schedule_profile):
    # The profile named 'strict' is exempt, since it is a special case. #
    if schedule_profile.name == QOS_STRICT:
        return

    queues = utils.get_column_data_from_row(schedule_profile, "queues")

    if len(queues) == 0:
        details = "The schedule profile must have at least one queue."
        raise ValidationError(error.VERIFICATION_FAILED, details)

    max_queue_num = get_max_queue_num(schedule_profile)

    algorithm = ""
    for queue_entry in queues.items():
        queue_num = queue_entry[0]
        schedule_profile_entry = queue_entry[1]

        schedule_profile_entry_algorithm = schedule_profile_entry.algorithm[0]

        # If it's the max and it's strict, then skip it. #
        if max_queue_num == queue_num and schedule_profile_entry_algorithm == QOS_STRICT:
            continue

        if algorithm == "":
            algorithm = schedule_profile_entry_algorithm

        if schedule_profile_entry_algorithm != algorithm:
            details = "The schedule profile must have the same algorithm on all queues."
            raise ValidationError(error.VERIFICATION_FAILED, details)

def get_max_queue_num(schedule_profile):
    max_queue_num = -1

    for queue_num in schedule_profile.queues.keys():
        if queue_num > max_queue_num:
            max_queue_num = queue_num

    return max_queue_num

def validate_queue_profile_contains_all_schedule_profile_queues(q_profile, schedule_profile):
    # The profile named 'strict' is exempt, since it is a special case. #
    if schedule_profile.name == QOS_STRICT:
        return

    queues = utils.get_column_data_from_row(schedule_profile, "queues")
    for queue_num in queues.keys():
        if not queue_profile_has_queue_num(q_profile, queue_num):
            details = "The queue profile must contain all of the schedule profile queue numbers."
            raise ValidationError(error.VERIFICATION_FAILED, details)

def validate_schedule_profile_contains_all_queue_profile_queues(q_profile, schedule_profile):
    # The profile named 'strict' is exempt, since it is a special case. #
    if schedule_profile.name == QOS_STRICT:
        return

    q_profile_entries = utils.get_column_data_from_row(q_profile, "q_profile_entries")
    for queue_num in q_profile_entries.keys():
        if not schedule_profile_has_queue_num(schedule_profile, queue_num):
            details = "The schedule profile must contain all of the queue profile queue numbers."
            raise ValidationError(error.VERIFICATION_FAILED, details)

def queue_profile_has_queue_num(q_profile, queue_num):
    q_profile_entries = utils.get_column_data_from_row(q_profile, "q_profile_entries")
    for profile_queue_num in q_profile_entries.keys():
        if queue_num == profile_queue_num:
            return True
    return False

def schedule_profile_has_queue_num(schedule_profile, queue_num):
    schedule_profile_entries = utils.get_column_data_from_row(schedule_profile, "queues")
    for profile_queue_num in schedule_profile_entries.keys():
        if queue_num == profile_queue_num:
            return True
    return False
