import io
from glob import glob
import os
import M2Crypto as m2
import json
from hashlib import sha1
from zipfile import ZipFile, ZIP_DEFLATED


class PkpassSigner:
    _m = None

    def __init__(self, cert, key, wwdr):
        self._m = m2.SMIME.SMIME()
        cs = m2.X509.X509_Stack()
        cs.push(m2.X509.load_cert(wwdr))

        self._m.load_key(key, cert)
        self._m.set_x509_stack(cs)

    def sign_folder(self, folder):
        with io.BytesIO() as data:
            with ZipFile(data, 'w', ZIP_DEFLATED) as r:
                for f in glob(os.path.join(folder, '**'), recursive=True):
                    if not os.path.isfile(f) or os.path.relpath(f, folder) in ['signature', 'manifest.json']:
                        continue
                    r.write(f, os.path.relpath(f, folder))
                manifest = self.create_manifest(r)
                r.writestr('manifest.json', manifest)
                r.writestr('signature', self.create_signature(manifest))
            return data.getvalue()


    def sign_pkpass(self, pkpass):
        with io.BytesIO() as result:
            with ZipFile(pkpass, 'a', ZIP_DEFLATED) as z:
                with ZipFile(result, 'w', ZIP_DEFLATED) as r:
                    for f in z.infolist():
                        if f.filename in ['signature', 'manifest.json']:
                            continue
                        r.writestr(f.filename, z.read(f))
                    manifest = self.create_manifest(r)
                    r.writestr('manifest.json', manifest)
                    r.writestr('signature', self.create_signature(manifest))
            return result.getvalue()

    def create_manifest(self, zipfile):
        manifest = {}
        for f in zipfile.infolist():
            if f.is_dir() or f.filename in ['signature', 'manifest.json']:
                continue
            with zipfile.open(f, 'r') as z:
                manifest[f.filename] = sha1(z.read()).hexdigest()
        mjson = json.dumps(manifest, indent=1).encode('utf-8')
        return mjson

    def create_signature(self, file):
        mb = m2.BIO.MemoryBuffer(file)

        pkcs7 = self._m.sign(mb, m2.SMIME.PKCS7_DETACHED | m2.SMIME.PKCS7_BINARY)

        mb = m2.BIO.MemoryBuffer()
        pkcs7.write_der(mb)
        return mb.read_all()
