import win32gui,win32ui,win32con,win32api,win32process,ctypes,subprocess,time
from PIL import Image
GAME=r"C:\Program Files (x86)\Steam\steamapps\common\San9WPK"
def SM(h,m,w,l):
    try: return win32gui.SendMessageTimeout(h,m,w,l,2,1500)
    except Exception as e: print('SM timeout',m)
def find(cls):
    r=[]
    win32gui.EnumWindows(lambda h,_:r.append(h) if win32gui.IsWindowVisible(h) and win32gui.GetClassName(h)==cls else None,None)
    return r[0] if r else None
def shot(h,path):
    l,t,r,b=win32gui.GetWindowRect(h);w,hh=r-l,b-t
    dc=win32gui.GetWindowDC(h);m=win32ui.CreateDCFromHandle(dc);s=m.CreateCompatibleDC()
    bm=win32ui.CreateBitmap();bm.CreateCompatibleBitmap(m,w,hh);s.SelectObject(bm)
    ctypes.windll.user32.PrintWindow(h,s.GetSafeHdc(),2)
    i=bm.GetBitmapBits(True);Image.frombuffer('RGB',(w,hh),i,'raw','BGRX',0,1).save(path)
    try: win32gui.DeleteObject(bm.GetHandle());s.DeleteDC();m.DeleteDC();win32gui.ReleaseDC(h,dc)
    except Exception: pass
    return w,hh
def click(h,x,y,hold=0.08):
    lp=win32api.MAKELONG(x,y)
    SM(h,win32con.WM_MOUSEMOVE,0,lp);time.sleep(0.05)
    SM(h,win32con.WM_LBUTTONDOWN,1,lp);time.sleep(hold)
    SM(h,win32con.WM_LBUTTONUP,0,lp)
def key(h,vk):
    SM(h,win32con.WM_KEYDOWN,vk,0);time.sleep(0.05);SM(h,win32con.WM_KEYUP,vk,0xC0000001)
def sclick(h,sx,sy):
    """click at screenshot coords (as seen in shot())"""
    l,t,_,_=win32gui.GetWindowRect(h);cx,cy=win32gui.ClientToScreen(h,(0,0))
    click(h,sx-(cx-l),sy-(cy-t))
