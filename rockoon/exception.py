class OpenStackControllerException(Exception):
    """A generic OpenStack Controller exception to be inherited from"""

    _msg_fmt = "An unknown exception occurred."

    def __init__(self, message=None, **kwargs):
        if not message:
            message = self._msg_fmt % kwargs
        super().__init__(message)


class TaskException(OpenStackControllerException):
    """A generic handler error exception"""


class OsDplValidationFailed(OpenStackControllerException):
    def __init__(self, message=None, code=400):
        super().__init__()
        self.message = message
        self.code = code


class HelmImmutableFieldChange(OpenStackControllerException):
    def __init__(self, message="Trying to change immutable object."):
        super().__init__()
        self.message = message


class HelmRollback(OpenStackControllerException):
    def __init__(self, message="Trying to rollback stuck release."):
        super().__init__()
        self.message = message


class OsdplSubstitutionFailed(OpenStackControllerException):
    def __init__(self, message="Trying to substitute osdpl fileds failed."):
        super().__init__()
        self.message = message


class PodExecCommandFailed(OpenStackControllerException):
    _msg_fmt = "Running command in pod returned stderr: %(stderr)s"
