import argparse
import hashlib
import json
import plistlib
import re
import struct
import zipfile
from pathlib import Path, PurePosixPath

parser = argparse.ArgumentParser()
parser.add_argument('ipa', type=Path)
parser.add_argument('--sha256')
parser.add_argument('--base', action='store_true')
parser.add_argument('--output', type=Path)
args = parser.parse_args()
digest = hashlib.file_digest(args.ipa.open('rb'), 'sha256').hexdigest()
if args.sha256 and digest != args.sha256.lower():
    raise SystemExit('IPA checksum mismatch')

def macho(data):
    base = 0
    if data[:4] == b'\xca\xfe\xba\xbe':
        base = struct.unpack_from('>I', data, 16)[0]
    if data[base:base + 4] != b'\xcf\xfa\xed\xfe':
        return None
    result = {'libraries': [], 'encrypted': False}
    pos = base + 32
    for _ in range(struct.unpack_from('<I', data, base + 16)[0]):
        cmd, size = struct.unpack_from('<II', data, pos)
        if size < 8 or pos + size > len(data):
            raise ValueError('Invalid Mach-O load command')
        if cmd in (0xc, 0x80000018, 0x8000001f, 0x80000023):
            off = struct.unpack_from('<I', data, pos + 8)[0]
            result['libraries'].append(data[pos + off:pos + size].split(b'\0')[0].decode(errors='replace'))
        if cmd == 0x2c:
            result['encrypted'] = bool(struct.unpack_from('<I', data, pos + 16)[0])
        pos += size
    return result

with zipfile.ZipFile(args.ipa) as archive:
    names = archive.namelist()
    if any(PurePosixPath(n).is_absolute() or '..' in PurePosixPath(n).parts for n in names):
        raise SystemExit('Unsafe archive member path')
    if sum(item.file_size for item in archive.infolist()) > 2 * 1024**3:
        raise SystemExit('Archive exceeds inspection size limit')
    if archive.testzip() is not None:
        raise SystemExit('Archive CRC validation failed')
    plist_path = next(n for n in names if n.startswith('Payload/') and n.endswith('.app/Info.plist') and n.count('/') == 2)
    info = plistlib.loads(archive.read(plist_path))
    app_path = plist_path.rsplit('/', 1)[0]
    executable = app_path + '/' + info['CFBundleExecutable']
    main = macho(archive.read(executable))
    frameworks = sorted({n.split('.framework/')[0] + '.framework' for n in names if '.framework/' in n})
    dylibs = [n for n in names if n.endswith('.dylib')]
    suspicious = [n for n in frameworks + dylibs if re.search(r'eevee|substrate|orion|audioprobe|vitrine|zxplugins|ellekit|spotipw', n, re.I)]
    encrypted = []
    binaries = {}
    for name in [executable] + dylibs + [n + '/' + n.rsplit('/', 1)[-1].removesuffix('.framework') for n in frameworks]:
        if name in names:
            parsed = macho(archive.read(name))
            if parsed:
                binaries[name] = parsed
                if parsed['encrypted']:
                    encrypted.append(name)
    report = {'sha256': digest, 'size': args.ipa.stat().st_size, 'bundle_id': info['CFBundleIdentifier'], 'version': info['CFBundleShortVersionString'], 'main_executable': main, 'frameworks': frameworks, 'dylibs': dylibs, 'encrypted_binaries': encrypted, 'tweak_components': suspicious, 'permission_descriptions': [k for k in info if k.startswith('NS') and 'UsageDescription' in k], 'limits': 'Static integrity and structural checks do not establish that an IPA is safe or unmodified.'}
    if args.base and (info['CFBundleIdentifier'] != 'com.spotify.client' or not main or encrypted or suspicious):
        print(json.dumps(report, indent=2))
        raise SystemExit('Base IPA failed structural checks')
    if not args.base and not any('EeveeSpotify.dylib' in n for n in dylibs):
        raise SystemExit('Eevee library missing from packaged IPA')
    serialized = json.dumps(report, indent=2)
    if args.output:
        args.output.write_text(serialized, encoding='utf-8')
    print(serialized)
