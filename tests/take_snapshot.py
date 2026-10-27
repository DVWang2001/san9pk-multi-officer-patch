"""Take the offline-test snapshot from a live game: slot 12, recruit dialog opened once (so its object holds a city context), then dump.
Usage: python take_snapshot.py   (needs snapdll.dll built; restores the patch DLL afterwards)"""
import sys, os, shutil, subprocess, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from runner import *
from PIL import Image, ImageChops
G = r"C:\Program Files (x86)\Steam\steamapps\common\San9WPK"
here = os.path.dirname(os.path.abspath(__file__))
patch_dll = os.path.join(here, 'patch_MyDoc.dll')
if not os.path.exists(patch_dll): shutil.copy(os.path.join(G, 'MyDoc.dll'), patch_dll)   # remember the installed patch DLL
for f in ('snap.bin', 'snap_truth.txt', 'snap_log.txt', 'snap_tid.txt', 'snap_dlg.txt', 'snap.go'):
    try: os.remove(os.path.join(G, f))
    except OSError: pass
if not os.path.exists(os.path.join(here, 'snapdll.dll')):
    subprocess.check_call([r'C:\MinGW\bin\gcc.exe', '-shared', '-O2', '-o', os.path.join(here, 'snapdll.dll'), os.path.join(here, 'snap.c'), os.path.join(here, '..', 'src', 'mydoc.def'), '-Wl,--enable-stdcall-fixup', '-lpsapi'])
shutil.copy(os.path.join(here, 'snapdll.dll'), os.path.join(G, 'MyDoc.dll'))
try:
    g = start(12); time.sleep(2)
    shot(g, os.path.join(here, 'snap_scene.png'))
    a = Image.open(os.path.join(here, 'snap_scene.png')).convert('RGB').crop((100, 40, 380, 70)); b = Image.open(os.path.join(here, 'ref_date_slot12.png')).convert('RGB')
    if ImageChops.difference(a, b).getbbox() is not None: raise SystemExit('wrong scene loaded (expected 223年10月中旬)')
    sclick(g, 520, 395); time.sleep(2.5); sclick(g, 552, 463); time.sleep(2); sclick(g, 620, 547); time.sleep(3)   # 登庸 dialog
    sclick(g, 338, 328); time.sleep(4); sclick(g, 770, 692); time.sleep(2); sclick(g, 672, 601); time.sleep(2.5)   # open target picker, cancel it, cancel dialog
    open(os.path.join(G, 'snap.go'), 'w').close()
    for _ in range(90):
        time.sleep(2)
        if os.path.exists(os.path.join(G, 'snap_log.txt')): break
    time.sleep(4)
    for f in ('snap.bin', 'snap_truth.txt', 'snap_tid.txt', 'snap_dlg.txt'): shutil.copy(os.path.join(G, f), os.path.join(here, f))
    print(open(os.path.join(G, 'snap_log.txt')).read())
finally:
    subprocess.call(['taskkill', '/F', '/IM', 'San9WPK.exe'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); time.sleep(2)
    shutil.copy(patch_dll, os.path.join(G, 'MyDoc.dll'))
    for f in ('snap.bin', 'snap_truth.txt', 'snap_log.txt', 'snap_tid.txt', 'snap_dlg.txt', 'snap.go'):
        try: os.remove(os.path.join(G, f))
        except OSError: pass
