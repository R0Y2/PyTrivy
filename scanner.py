#!/usr/bin/env python3
"""
  Install trivy and scan the system
  Compatible systems:
    - Amazon Linux | x86/Arm
    - Ubuntu | x86/Arm
  Usage: sudo python3 scanner.py
"""
import os
import shutil
import tempfile
import subprocess
import urllib.request as ur


class Scanner():
  def __init__(self, name, version, url):
    self.name = name
    self.version = version
    self.url = url

  def get_arch(self):
    return '64bit' if os.uname().machine == 'x86_64' else 'ARM64'

  def get_suffix(self):
    with open('/etc/os-release') as f:
      l = f.readline().rstrip('\n')
    return 'rpm' if 'Amazon Linux' in l else 'deb'

  def get_url(self):
    return self.url.format(
      **{
        'name':    self.name,
        'version': self.version,
        'arch':    self.get_arch(),
        'suffix':  self.get_suffix(),
      }
    )

  def run_cmd(self, cmd):
    p = subprocess.Popen(cmd.split())
    p.wait()
    if p.returncode != 0:
      raise subprocess.CalledProcessError(p.returncode, cmd)

  def download(self):
    plink = self.get_url()
    ppath = f"/tmp/{plink.split('/')[-1]}"
    with ur.urlopen(plink) as res:
      with tempfile.NamedTemporaryFile(delete=False, suffix=f'.{self.get_suffix()}') as tf:
        shutil.copyfileobj(res, tf)
    shutil.move(tf.name, ppath)
    return ppath

  def install(self, pkg):
    install_cmd = 'dpkg -i' if self.get_suffix() == 'deb' else 'dnf install -y'
    self.run_cmd(f'{install_cmd} {pkg}')

  def scan(self, scan_cmd):
    self.run_cmd(scan_cmd)


def main(parsed_args=None):
  s = Scanner(
    'trivy', 
    '0.53.0', 
    'https://github.com/aquasecurity/{name}/releases/download/' \
            'v{version}/{name}_{version}_Linux-{arch}.{suffix}'
  )
  s.install(pkg=s.download())
  s.scan('trivy filesystem / --scanners vuln -q --ignore-unfixed')


if __name__ == '__main__':
  try:
    main()
  except Exception as e:
    print(repr(e))
