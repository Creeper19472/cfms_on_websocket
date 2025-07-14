import gettext

t = gettext.translation('cfms_server', "include/locale", fallback=True)
_ = t.gettext


SUCCESS = _("Success")

SUBJECT_DIRECTORY_NOT_FOUND = _("Subject directory not found")

TARGET_OBJECT_NOT_FOUND = _("Target object not found")
TARGET_DIRECTORY_NOT_FOUND = _("Target directory not found")
TARGET_DOCUMENT_NOT_FOUND = _("Target document not found")

INVALID_USER_OR_TOKEN = _("Invalid user or token")

ACCESS_DENIED = _("Access denied")
ACCESS_DENIED_MOVE_DOCUMENT = _("Access denied to move document")
ACCESS_DENIED_MOVE_DIRECTORY = _("Access denied to move directory")
ACCESS_DENIED_WRITE_DIRECTORY = _("Access denied to write directory")
