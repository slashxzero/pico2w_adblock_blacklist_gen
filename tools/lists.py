#!/usr/bin/env python3
"""Resolve lists.conf (+ optional overrides from a manual workflow run) into source URLs.

usage: lists.py lists.conf urls.txt summary.txt
  Overrides come from the environment: IN_HAGEZI, IN_TIF, IN_STEVENBLACK, IN_EXTRA.
  Empty or "(keep)" keeps the value in lists.conf; anything else is validated and saved
  back into lists.conf (so the weekly scheduled runs keep using it).
"""
import os, re, sys

HAGEZI = 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/{}-onlydomains.txt'
STEVENBLACK = 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts'
CHOICES = {
    'HAGEZI': {'light', 'pro', 'pro.plus', 'ultimate', 'none'},
    'TIF': {'none', 'tif.mini'},
    'STEVENBLACK': {'yes', 'no'},
}
URL = re.compile(r'^https://[A-Za-z0-9._~:/?#@!&+,=%-]+$')       # no quotes, $, ( ) or ;

def fail(msg):
    print(f'!! {msg}', file=sys.stderr); sys.exit(1)

def check(key, value):
    if key == 'EXTRA':
        for u in value.split():
            if not URL.match(u): fail(f'EXTRA: not an https:// URL: {u!r}')
    elif value not in CHOICES[key]:
        fail(f'{key}={value!r}: must be one of {sorted(CHOICES[key])}')

def main():
    conf_path, urls_path, summary_path = sys.argv[1:4]
    lines = open(conf_path, encoding='utf-8').read().splitlines()
    conf = {}
    for line in lines:
        m = re.match(r'^\s*([A-Z]+)\s*=(.*)$', line)
        if m and m.group(1) in (*CHOICES, 'EXTRA'): conf[m.group(1)] = m.group(2).strip()
    for key in (*CHOICES, 'EXTRA'):
        conf.setdefault(key, '')
        override = os.environ.get(f'IN_{key}', '').strip()
        if override and override != '(keep)':
            conf[key] = '' if (key == 'EXTRA' and override == '-') else override
        check(key, conf[key])

    # write overrides back, keeping comments and layout
    out = []
    for line in lines:
        m = re.match(r'^\s*([A-Z]+)\s*=', line)
        out.append(f'{m.group(1)}={conf[m.group(1)]}' if m and m.group(1) in conf else line)
    open(conf_path, 'w', encoding='utf-8').write('\n'.join(out) + '\n')

    urls, names = [], []
    if conf['STEVENBLACK'] == 'yes': urls.append(STEVENBLACK); names.append('StevenBlack')
    if conf['HAGEZI'] != 'none': urls.append(HAGEZI.format(conf['HAGEZI'])); names.append(f'Hagezi {conf["HAGEZI"]}')
    if conf['TIF'] != 'none': urls.append(HAGEZI.format(conf['TIF'])); names.append(f'Hagezi {conf["TIF"]}')
    for u in conf['EXTRA'].split(): urls.append(u); names.append(u)
    if not urls: fail('no sources selected')
    open(urls_path, 'w').write('\n'.join(urls) + '\n')
    open(summary_path, 'w').write(' + '.join(names) + '\n')
    print(' + '.join(names))

if __name__ == '__main__':
    main()
