#########   >>>>>>>>>>> written by imcyber0wl on github. 
import tkinter as tk
from tkinter import ttk
from tkinter import *
from icmplib import ping
from random import randbytes
import multiprocessing
import time
import threading
from tkinter.messagebox import showerror, showwarning, showinfo
import os
import re
import sys
from scapy.all import *
#########   >>>>>>>>>>> written by imcyber0wl on github. 
exitflag=0
img_path=os.getcwd()

#root window
root_win=tk.Tk()
root_win.title("OpenEye v2")
root_win.geometry('750x245+450+200')
try:
    root_win.iconbitmap(img_path+'\openeye.ico')
except:
    print("couldnt load icon (openeye.ico) from ",img_path)
    
root_win.resizable(False,False)
style = ttk.Style(root_win)
style.theme_use("xpnative")


#globals

routerip=0


global ip_list2
global mac_list
global routerisset #to know if router is found or not

routerisset=0
ip_list2=['']*255
mac_list=['']*255


#Font sets
fontset4=("Arial",16,"bold")
fontset3=("Arial",16)
fontset2=("Arial",14,"bold")
fontset5=("Arial",10,"bold")

#Frames
root=ttk.Frame(root_win,height=250,width=725)
root.place(x=0,y=0)

#Main text
lbl1= tk.Label(root, text="Router: ",font = fontset3)
lbl2= tk.Label(root, text="Internet: ",font = fontset3)

onlbl= tk.Label(root, text="ON")
onlbl2= tk.Label(root, text="ON")
onlbl.configure(font = fontset4,fg="green")
onlbl2.configure(font = fontset4,fg="green")

timelbl=tk.Label(root,text="Speed: ",font = fontset3)
speedlbl=tk.Label(root,text="---",font = fontset4,width=5)
speedlbl2=tk.Label(root,text="1MB per",font = fontset3)
fsl=tk.Label(root,text="second/s",font = fontset3)

#grid labels
lbl1.place(x=5, y=30)
lbl2.place(x=5, y=60)
timelbl.place(x=5,y=2)
speedlbl.place(x=160,y=2)
speedlbl2.place(x=80,y=2)
fsl.place(x=220,y=2)


#Canvas
canvas = Canvas(root,highlightthickness=1, highlightbackground="black",width=390,height=150)
canvas.create_rectangle(0,150,420,0,width=0,fill="white")
canvas.place(x=5,y=90)

canvas_f = canvas


##########   Second Part  (Devices connected)  ########

canvas3= Canvas(root_win,width=0.5,height=233,bg="black")
canvas3.create_line(0, #x1
                    0, #y1
                    1, #x2
                    245#y2
                    , width=0.5,fill="black")
canvas3.place(x=400,y=1)


condevs=tk.Label(root, text="Devices on Network", font=fontset3)
condevs.place(x=474,y=4)

### Textboxes 
textbx=tk.Text(root, height =13 , width = 25,font=fontset5) #for ip
textbx2=tk.Text(root, height =13 , width = 25,font=fontset5) #for mac

#for scroll bar to scroll 2 widgets at same time
def s_viewall(*args):
    global textbx, textbx2
    eval('textbx.yview(*args)')
    eval('textbx2.yview(*args)')

### Scrollbar 
scrl=ttk.Scrollbar(root,orient='vertical',command=s_viewall)#(textbx.yview , textbx2.yview))
textbx.configure(yscrollcommand=scrl.set)
textbx2.configure(yscrollcommand=scrl.set)
scrl.place(x=710,y=30,height=212)


########################  Functions  ##################

########### Get router IP and user's IP 
def scan_router():
    ds=['','']
    global exitflag
    if exitflag!=1:
        with os.popen('arp -a') as f:
            data=f.read()

        for line in re.findall('([-.0-9]+)\s',data): #get your ip
            ds[0]=ds[0]+line
            break

        #get router IP 
        for line in re.findall('([-.0-9]+)\s+([-0-9a-f]{17})\s+(\w+)',data):
            ds[1]=ds[1]+line[0]
            break
                
        return ds[0],ds[1]
    else:
        return ('0','0')


###Get Router Ip and MAC, and User IP and MAC
your_ip,router_ip=scan_router()
print("router ip: ",router_ip)
print("your ip: ",your_ip)


################ Get MAC of user and Router
def get_macs(routerip,yourip):
    x=0
    x1=0 #to know if user mac is known
    x2=0 #to know if router's mac is known
    ips_a=[yourip,routerip]
    if True:
        #get user mac
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=ips_a[x])
        arp_response = srp(arp_request, timeout=2, verbose=False)[0]
        for sent, received in arp_response:
            _mac = received.hwsrc
            ips_a[x]=_mac
            x1=1

        x+=1
        #get router mac
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=ips_a[x])
        arp_response = srp(arp_request, timeout=2, verbose=False)[0]
        for sent, received in arp_response:
            _mac = received.hwsrc
            ips_a[x]=_mac
            x2=1 
    if x1==1 and x2==1:
        return ips_a[0],ips_a[1]
    else:
        print("retrying to get MACS")
        ips_a[0],ips_a[1]=get_macs(routerip,yourip)
        return ips_a[0],ips_a[1]
    
your_mac,router_mac=get_macs(router_ip,your_ip)
mac_list[1]=router_mac
mac_list[0]=your_mac
print("router mac: ",router_mac)
print("user mac: ",your_mac)


######### Put the IPs and MACs in textboxes (and place textboxes)
def placecds():
    global your_ip
    global router_ip
    global ip_list2
    global mac_list
    global your_mac
    global router_mac
    ips=your_ip +' (you)\n'+ router_ip+' (router)\n'
    macs=your_mac+'\n'+router_mac+'\n' 
    x=0
    textbx.configure(state="normal")
    textbx2.configure(state="normal")
    #trying to insert into the textbox while its state is disabled doesnt work
    
    while x!=255:
        if ip_list2[x]!='':
            ips=ips+ip_list2[x]+'\n'
            macs=macs+mac_list[x]+'\n'
        x+=1

    textbx.delete('0.0', tk.END)
    textbx.insert('0.0', ips)
    
    textbx2.delete('0.0', tk.END)
    textbx2.insert(tk.END, macs)

    textbx.configure(state="disable")
    textbx.place(x=410,y=30)

    textbx2.configure(state="disable")
    textbx2.place(x=560,y=30)

placecds()


################ Check if router is working or not
def checkroute(routerip):
    global exitflag
    while exitflag!=1:
        try:
            print("router ip: ",routerip)
            x=ping(routerip,count=1,payload=randbytes(10))
            if x.packets_received>0:
                onlbl.configure(text="ON",fg="green")
                onlbl.place(x=90, y=30)
                print("router is on")
            else:
                onlbl.configure(text="OFF",fg="red")
                onlbl.place(x=90, y=30)
                print("router is off")
        except:
            print("couldnt ping router")
            onlbl.configure(text="OFF",fg="red")
            onlbl.place(x=90, y=30)
            
        time.sleep(10)
    

###### Draw on Canvas
def checknet():
    conte=0
    global exitflag
    canvas_f = canvas
    payload=randbytes(1000-28)  #28 is size of ICMP frame    
    while exitflag!=1:
        try:
            ####x=0 #needed for conversion in case a packet was lost
            y=ping('google.com',count=5,payload=payload,interval=0)
            if y.packets_received!=5:
                x=(5-(5-y.packets_received))*40
            else:
                x=0
            speed=y.avg_rtt*(200+x)  #*200 because we sent 5 kilobytes
            speed=speed/1000  #convert from miliseconds to seconds
            speedlbl.configure(text=str(float(f'{speed:.2f}')))
            speedlbl.place(x=160,y=2)

            #Draw on the screen
            conte=conte+5
            if conte>=390:
                conte=5
                
                canvas_f.create_rectangle(0,250,420,0,width=0,fill="white")
                canvas_f.place(x=5,y=90)
                #rectangle height (y) is 250

            
            if speed>=20 and speed<40:  #if speed is 1mb per 30+ seconds
                canvas_f.create_line(conte, #x1
                               150, #y1
                               conte, #x2
                               speed*2 #y2
                               , width=4,fill="orange")
                canvas_f.place(x=5,y=90)
            elif speed>=40:
                canvas_f.create_line(conte, #x1
                               150, #y1
                               conte, #x2
                               speed*2#y2
                               , width=4,fill="red")
                canvas_f.place(x=5,y=90)                
            else:
                canvas_f.create_line(conte, #x1
                               150, #y1
                               conte, #x2
                               speed*2#y2
                               , width=4,fill="green")
                canvas_f.place(x=5,y=90)

            print("speed: 1 megabyte per ",speed, " second/s" )
            if y.packets_received!=0:
                onlbl2.configure(text="ON",fg="green")
                onlbl2.place(x=90, y=60)
            else:
                onlbl2.configure(text="OFF",fg="red")
                onlbl2.place(row=2, y=2)
                speedlbl.configure(text="---")
                speedlbl.place(x=160,y=2)
                canvas_f.create_line(conte, #x1
                               150, #y1
                               conte, #x2
                               0 #y2
                               , width=4,fill="red")
                canvas_f.place(x=5,y=90)                
        except:
            onlbl2.configure(text="OFF",fg="red") 
            print("couldnt ping google!")
            onlbl2.place(x=90, y=60)
            speedlbl.configure(text="101010")
            speedlbl.place(x=160,y=2)
            canvas_f.create_line(conte, #x1
                               150, #y1
                               conte, #x2
                               0 #y2
                               , width=4,fill="red")
            canvas_f.place(x=5,y=90)            
            
        time.sleep(3)


########## Scan network for other users
def scan_others(routerip,yourip):
    global ip_list2
    global mac_list

    #We know router ip starts with 192.168.
    #this loop finds the next part
    ip_list=0 #number to start from
    x=8
    target_ip='192.168.'
    while routerip[x]!='.' and x<len(routerip):
        target_ip=target_ip+routerip[x]
        x+=1
    
    target_ip=target_ip+"."

    #Threads to make scanning faster
    t_1=threading.Thread(target=scan_thread,args=(0,66,routerip,yourip,target_ip))
    t_2=threading.Thread(target=scan_thread,args=(67,130,routerip,yourip,target_ip))
    t_3=threading.Thread(target=scan_thread,args=(131,194,routerip,yourip,target_ip))
    t_4=threading.Thread(target=scan_thread,args=(195,255,routerip,yourip,target_ip))
    t_1.start()
    t_2.start()
    t_3.start()
    t_4.start()


############# This function is used in threads that scan
def scan_thread(i,n,routerip,yourip,target_ip):
    #i is ip to beginning scan
    #n is limit to stop scanning
    #start scanning:
    global ip_list2
    global mac_list
    ip_list=i
    while ip_list!=n+1:
        if target_ip+str(ip_list)!=routerip and target_ip+str(ip_list)!=yourip:

            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=target_ip+str(ip_list))
            try:
                arp_response = srp(arp_request, timeout=1, verbose=False)[0]
            except:
                print("Something is wrong, couldnt send ARP Who-has packet")
                
            for sent, received in arp_response:

                target_mac = received.hwsrc
                mac_list[ip_list]=target_mac
                ip_list2[ip_list]=(target_ip+str(ip_list))
                placecds()

            ip_list+=1

        else:
            ip_list+=1

          
################# start scanning forever
def scan_others_1(routerip,yourip):
    global exitflag
    global ip_list2
    global mac_list
    while exitflag!=1:
        scan_others(router_ip,your_ip)
        time.sleep(145)
        #empty ip and mac lists for renewal
        ip_list2=['']*255
        mac_list=['']*255
        

#**********************************************************#


thread1=threading.Thread(target=checkroute,args=((router_ip),))
thread1.start()
time.sleep(0.5)

thread2=threading.Thread(target=checknet)
thread2.start()
time.sleep(0.3)

thread3=threading.Thread(target=scan_others_1,args=((router_ip,your_ip)))
thread3.start()


root_win.mainloop()
exitflag=1
sys.exit()
