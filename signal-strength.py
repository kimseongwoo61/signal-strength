# -*- coding: utf-8 -*-
"""
Created on Thu Jan  5 17:30:21 2023
@author: kimse
BSSID, Beacons=?, (#Data=?), (ENC=?), ESSID, (PWR=atenna signal) 
"""

import socket, sys, os

PACKET_INFO = []

def analyzer_80211(pkt, ch, interface_name, mac):
    flag = 0
    CLR = "\x1B[0K"
    count_x = 0
    count_y = 0
    
    packetInfo = packet802()
    packetInfo.setInfomember(pkt)
    temp = [packetInfo.BSSID, packetInfo.Beacons, packetInfo.Data, 
            packetInfo.ESSID, packetInfo.PWR, packetInfo.ENC, ch]
        
    
    if(packetInfo.Type == b'\x80' or packetInfo.Type == b'\x88'):
        if(flag == 0):
            PACKET_INFO = temp
            #PACKET_INFO.sort(key=lambda x:x[5])
            #print("interface Name : {}{}".format(interface_name, CLR))
            

            if(PACKET_INFO[0] == mac):
                print("{}'s PWR : {}".format(mac, PACKET_INFO[4]))

    
    else:
        return
    
    
def printInterface(interface_name, mac):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    s.bind((interface_name,0x0003))
    
    try:
        while True:    
            for channel in range(1, 13):
                os.system("iwconfig " + interface_name + " channel " + str(channel))
                packet = s.recvfrom(2048)[0]
                analyzer_80211(packet, channel, interface_name, mac)
    
    except KeyboardInterrupt:
        s.close()
        exit(0)
            
class packet802():
    headerSize = 0
    Type = 0
    BSSID = ""
    Beacons = 0
    Data = 0
    ESSID = ""
    PWR = 0
    
    def __init__(self): 
        self.BSSID = ""
        self.Beacons = 0
        self.Data = 0
        self.ESSID = ""
        self.PWR = 0
        self.ENC = ""
       
    def setInfomember(self, pkt): 
        self.headerSize = int.from_bytes(pkt[2:4], byteorder='little', signed=True)
        self.Type = pkt[self.headerSize:self.headerSize+1]
        self.PWR = int.from_bytes(pkt[18:19], byteorder='big', signed=True)
        
        if(self.Type == b'\x80'): #beacon
            self.BSSID = pkt[40:46].hex(":")
            self.ESSID = bytearray.fromhex(pkt[62:62+ int(pkt[61:62].hex(), 16)].hex()).decode()
            
            index = 62 + int(pkt[61:62].hex(), 16)
            size = 0
            try:
                while(True):
                    if(pkt[index:index+1] == b''):
                        self.ENC = "OPT"
                        break
                    
                    
                    elif(pkt[index:index+1] == b'\x30'): #RSN tag
                        if(pkt[index+7:index+8] == b'\x01'):
                            self.ENC = "WEP"
                        
                        elif(pkt[index+7:index+8] == b'\x02'):
                            self.ENC = "WPA - TKIP"
                                                     
                        elif(pkt[index+7:index+8] == b'\x03'):
                            self.ENC = "WRAP"
                        
                        elif(pkt[index+7:index+8] == b'\x04'):
                            self.ENC = "WPA2 - CCMP"
                        
                        elif(pkt[index+7:index+8] == b'\x05'):
                            self.ENC = "WEP104"
                        
                        elif(pkt[index+7:index+8] == b'\x09'):
                            self.ENC = "WPA2 - GCMP"
                        
                        elif(pkt[index+7:index+8] == b'\x0c'):
                            self.ENC = "WPA2 - GMAC"
                        
                        else:
                            self.ENC = "????"
                        
                        break
                    
                    
                    else:
                        index += 1
                        size = int.from_bytes(pkt[index:index+1], byteorder='little', signed=True)
                        index += size + 1
                    
            except:
                self.ENC = "????"
            
            
        elif(self.Type == b'\x88'): #Qos data
            self.BSSID = pkt[31:37].hex(":")




printInterface(sys.argv[1], sys.argv[2].lower())
