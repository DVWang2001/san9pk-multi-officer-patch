import sys
from winlib import *
def start(slot=15):
    subprocess.call(["taskkill","/F","/IM","San9WPK.exe"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);time.sleep(2)
    subprocess.Popen([GAME+r"\San9WPK_Launcher.exe"],cwd=GAME)
    for _ in range(30):
        time.sleep(1);h=find("KOEI__San9WPK_LAUNCHER_WINDOW")
        if h:break
    time.sleep(1.5)
    b=win32gui.FindWindowEx(win32gui.GetWindow(h,5),0,"Button","GAME");SM(b,win32con.BM_CLICK,0,0)
    for _ in range(60):
        time.sleep(1);g=find("KOEI_SAN9WINDOW")
        if g:break
    time.sleep(6)
    for _ in range(8):
        shot(g,"_t.png");im=Image.open("_t.png").convert("RGB")
        if im.getpixel((150,223))[2]>150 and im.getpixel((150,223))[0]<80: break
        click(g,900,700);time.sleep(2.5)
    sclick(g,190,267);time.sleep(3)
    page=(slot-1)//5
    sclick(g,[546,606,666,726,786,846,906,966][page],650);time.sleep(2)
    sclick(g,500,160+104*((slot-1)%5));time.sleep(5);sclick(g,520,420);time.sleep(1.5)
    goto_ruler(g)
    return g
def open_city(g):
    """click the ruler's city wherever the camera put it: find the city menu by colour after a click at the label"""
    for (x,y) in ((520,375),(520,240),(520,300)):
        sclick(g,x,y);time.sleep(2.5);shot(g,"_m.png")
        im=Image.open("_m.png").convert("RGB")
        if sum(im.getpixel((140,180)))<60 and sum(im.getpixel((150,662)))<40:   # dark 都市 info panel on the left
            return (x,y)
        key(g,27);time.sleep(1)
    return None
def city_cmd(g,which):
    """open the ruler's city menu and click 人材->探索 (which='explore') or 人材->登庸 ('recruit')"""
    p=open_city(g)
    if not p: raise RuntimeError("city not found")
    x,y=p
    sclick(g,x+32,y+68);time.sleep(2)
    sclick(g,x+100,y+(124 if which=="explore" else 152));time.sleep(3)
    return p
def goto_ruler(g):
    sclick(g,957,280);time.sleep(1.5);sclick(g,935,338);time.sleep(3)
if __name__=="__main__":
    g=start(int(sys.argv[1]));shot(g,"run.png");print("ok")
