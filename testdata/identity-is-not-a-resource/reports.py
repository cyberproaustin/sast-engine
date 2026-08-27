"""The collaborator both handlers talk to."""


def validate_report_belongs_to_project(report_id, project_id):
    return True


def read(report_id):
    return ""


def save(report_id, project_id, body):
    return ""


def permitted_document_ids(user):
    return []


def touch_document(user):
    return None
