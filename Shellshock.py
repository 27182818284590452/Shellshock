#!/usr/bin/env python2
# -*- coding: utf-8 -*-

#####################################
#                                   #
#           Shellstorm API          #
#          by: 314159265358Pi       #
#                                   #
#####################################

import sys
import httplib

class Shellshock():
    def __init__(self):
        pass

    def searchShellcode(self, keyword):
        try:
            print "Connecting to shell-storm.org..."
            s = httplib.HTTPConnection("shell-storm.org")
            s.request("GET", "/api/?s="+str(keyword))
            res = s.getresponse()
            data_l = res.read().split('\n')
        except:
            print "Cannot connect to shell-storm.org"
            return None

        data_dl = []
        for data in data_l:
            try:
                desc = data.split("::::")
                try:
                    dico = {
                             'ScAuthor': desc[0],
                             'ScArch': desc[1],
                             'ScTitle': desc[2],
                             'ScId': desc[3],
                             'ScUrl': desc[4],
                             'ScSize': int(''.join(x for x in desc[2][-10:-5] if x.isdigit()))
                           }
                except Exception:
                    dico = {
                             'ScAuthor': desc[0],
                             'ScArch': desc[1],
                             'ScTitle': desc[2],
                             'ScId': desc[3],
                             'ScUrl': desc[4],
                             'ScSize': 0
                           }


                data_dl.append(dico)
            except:
                pass

        try:
            return sorted(data_dl, key=lambda x: x['ScSize'], reverse=True)
        except Exception:
            print("Could not sort by size")

        return data_dl

    def displayShellcode(self, shellcodeId):
        if shellcodeId is None:
            return None

        try:
            print "Connecting to shell-storm.org..."
            s = httplib.HTTPConnection("shell-storm.org")
        except:
            print "Cannot connect to shell-storm.org"
            return None

        try:
            s.request("GET", "/shellcode/files/shellcode-"+str(shellcodeId)+".php")
            res = s.getresponse()
            data = res.read().split("<pre>")[1].split("<body>")[0]
        except:
            print "Failed to download shellcode from shell-storm.org"
            return None

        data = data.replace("&quot;", "\"")
        data = data.replace("&amp;", "&")
        data = data.replace("&lt;", "<")
        data = data.replace("&gt;", ">")

        return data

class Color():
    @staticmethod
    def red(str):
        return "\033[91m" + str + "\033[0m"

    @staticmethod
    def green(str):
        return "\033[92m" + str + "\033[0m"

    @staticmethod
    def yellow(str):
        return "\033[93m" + str + "\033[0m"

    @staticmethod
    def blue(str):
        return "\033[94m" + str + "\033[0m"

def screen():
        api = Shellshock()
        color = Color()
        
        print("\033[94m   _____ _          _ _     _                _    ")
        print("  / ____| |        | | |   | |              | |   ")
        print(" | (___ | |__   ___| | |___| |__   ___   ___| | __")
        print("  \___ \| '_ \ / _ \ | / __| '_ \ / _ \ / __| |/ /")
        print("  ____) | | | |  __/ | \__ \ | | | (_) | (__|   < ")
        print(" |_____/|_| |_|\___|_|_|___/_| |_|\___/ \___|_|\_|\033[0m")
        print("\033[93m----------------------------------------------------------------------\033[0m")
        print("\033[92m[1] Search for a shellcode")
        print("[2] Display a specific shellcode")
        print("[3] Quit\033[0m")
        print("\033[93m----------------------------------------------------------------------\033[0m")
        mod = int(raw_input("Enter your choice: "))
        if mod < 1 or mod > 4:
            print("[!] Please enter a valid number")
            screen()

        elif mod == 1:
            keywords = str(raw_input(color.green("Please enter your keywords: ")))
            res_dl = api.searchShellcode(keywords)
            if not res_dl:
                print(color.red("Shellcode not found"))
                sys.exit(0)

            print "Found %d shellcodes" % len(res_dl)
            print "%s\t%s %s" %(Color.blue("ScId"), Color.blue("Size"), Color.blue("Title"))
            for data_d in res_dl:
                if data_d['ScSize'] == 0:
                    print "[%s]\tn/a  %s - %s" %(Color.yellow(data_d['ScId']), data_d['ScArch'], data_d['ScTitle'])

                else:
                    print "[%s]\t%s%s - %s" %(Color.yellow(data_d['ScId']), str(data_d['ScSize']).ljust(5), data_d['ScArch'], data_d['ScTitle'])
            screen()


        elif mod == 2:
            shellcodeID = int(raw_input("Please enter the shellcode id: "))
            res = api.displayShellcode(shellcodeID)
            if not res:
                print "Shellcode id not found"
                sys.exit(0)
            print "%s" %(Color.blue(res))
            screen()
        
        elif mod == 3:
            sys.exit(0)

screen()
