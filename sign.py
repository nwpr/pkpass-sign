import io
from glob import glob
import os
import M2Crypto as m2
import json
from hashlib import sha1
from zipfile import ZipFile, ZIP_DEFLATED


class PkpassSigner:
    KEYPATH = None
    KEY_FILE = None
    WWDR_FILE = None

    def __init__(self, cert, key, wwdr):
        self.cert = m2.X509.load_cert(cert)
        self.key = m2.EVP.load_key(key)
        self.wwdr = m2.X509.load_cert(wwdr)

    def sign_folder(self, folder):
        data = io.BytesIO()
        zip = ZipFile(data, 'w', ZIP_DEFLATED)
        for f in glob(os.path.join(folder, '*')):
            zip.write(f, os.path.relpath(f, folder))


    def sign_pkpass(self, pkpass):
        with ZipFile(pkpass, 'a', ZIP_DEFLATED) as z:
            manifest = self.create_manifest(z)
            z.writestr('manifest.json', manifest.read())
            z.writestr('signature', self.create_signature(manifest).read())

    def create_manifest(self, zipfile):
        manifest = {}
        for f in zipfile.infolist():
            if f.is_dir():
                continue
            with zipfile.open(f, 'rb') as z:
                manifest[f.filename] = sha1(z.read()).hexdigest()
        mjson = json.dumps(manifest, indent=1)
        bytes = io.BytesIO()
        bytes.write(mjson)
        return bytes

    def create_signature(self, file):
        m = m2.SMIME.SMIME()
        cs = m2.X509.X509_Stack()
        wwdr = open(os.path.join(self.KEYPATH, self.WWDR_FILE), 'rb').read()
        cs.push(m2.X509.load_cert_string(wwdr))

        m.load_key(os.path.join(self.KEYPATH, self.KEY_FILE))
        m.set_x509_stack(cs)

        mb = m2.BIO.MemoryBuffer(file)

        pkcs7 = m.sign(mb, m2.SMIME.PKCS7_DETACHED | m2.SMIME.PKCS7_BINARY)

        mb = m2.BIO.MemoryBuffer()
        pkcs7.write_der(mb)
        w = io.BytesIO()
        w.write(mb.read_all())
        w.close()
        return w
