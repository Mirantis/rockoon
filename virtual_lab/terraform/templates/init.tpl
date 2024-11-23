#cloud-config
write_files:
  - encoding: b64
    content: ${ssh_private_key_base64}
    path: /root/.ssh/id_rsa
    permissions: '0400'

