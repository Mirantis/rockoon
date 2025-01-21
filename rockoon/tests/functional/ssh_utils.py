import paramiko
from io import StringIO


def generate_keys():
    file_obj = StringIO()
    key = paramiko.RSAKey.generate(1024)
    key.write_private_key(file_obj)
    public = key.get_base64()
    private = file_obj.getvalue()
    file_obj.close()
    return {"private": private, "public": public}
