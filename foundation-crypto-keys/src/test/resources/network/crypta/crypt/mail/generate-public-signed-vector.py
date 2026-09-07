#!/usr/bin/env python3
"""Reference generator for public synthetic signed Mail; no production module imports."""
import base64
import hashlib
import json
import pathlib
import subprocess
import tempfile

SEED = bytes.fromhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')
PUBLIC = bytes.fromhex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')
fields = dict(profile='crypta.mail.message.v1', messageId='01'*16,
              sender=hashlib.sha256(b'signing\n'+PUBLIC).hexdigest(),
              senderAccount='02'*16, senderEpoch='1', recipient='03'*32,
              recipientAccount='04'*16, recipientEpoch='1', created='100', expires='200',
              subject='Public synthetic subject', body='<script>inert text</script>', format='text/plain')
payload = json.dumps(fields, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
preimage = b'crypta.mail.message.v1\n' + payload
with tempfile.TemporaryDirectory() as tmp:
    root = pathlib.Path(tmp)
    (root/'key.der').write_bytes(bytes.fromhex('302e020100300506032b657004220420')+SEED)
    (root/'preimage').write_bytes(preimage)
    signature = subprocess.check_output(['openssl', 'pkeyutl', '-sign', '-rawin', '-inkey', str(root/'key.der'), '-keyform', 'DER', '-in', str(root/'preimage')])
wrapper = json.dumps(dict(payload=base64.b64encode(payload).decode(), signature=base64.b64encode(signature).decode()), separators=(',', ':')).encode()
out = pathlib.Path(__file__).with_name('public-signed-message.json')
out.write_bytes(wrapper)
print(hashlib.sha256(wrapper).hexdigest())
