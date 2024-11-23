import uuid


def rand_name(prefix="test-functional", postfix=""):
    return "{}-{}-{}".format(prefix, postfix, str(uuid.uuid4()))
