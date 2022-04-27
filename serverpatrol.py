#!/usr/local/bin/python3
import pymysql,smtplib
from email.mime.text import MIMEText
from scapy.all import *
from random import randint
from multiprocessing import Pool

def getMysql(col,tablesName,item=None):
    host,user,password,port='172.17.0.1','root','root',3306
    mysql = pymysql.connect (host=host, user=user, password=password, port=port)
    cursor = mysql.cursor()
    sql = "select {} from {} {};".format(col,tablesName,item)
    cursor.execute(sql)
    results = cursor.fetchall()
    cursor.close()
    mysql.close()
    return results

def updateMysql(tablesName,fieldValue,itemValue):
    mysql = pymysql.connect (host=host, user=user, password=password, port=port)
    cursor = mysql.cursor()
    sql = 'update {} set checkNum={} where ip={};'.format(tablesName,fieldValue,itemValue)
    cursor.execute(sql)
    mysql.commit()
    cursor.close()
    mysql.close()

def getServer():
    results=getMysql('ip,os,checkNum','django.app01_serverinfo')
    serverList=[]
    for i in results:
        if i[1] == 1:
            serverList.append({"ip":i[0],"port":"3389","checkNum":i[2]})
        else:
            serverList.append({"ip":i[0],"port":"22","checkNum":i[2]})
    return serverList

def getEmailbody():
    results=getMysql('ip,checkNum','django.app01_serverinfo','where checkNum!=0')
    emailBody=''
    if results:
        emailBody='异常情况'
        for i in results:
            if i[1] == 1:
                emailBody+="\n"+i[0]+" ping 异常"
            elif i[1] == 2:
                emailBody+="\n"+i[0]+" 远程 异常"
            else:
                emailBody+="\n"+i[0]+" ping 远程 异常"
    return emailBody

def sendMail(emailBody):
    mail_host = 'smtp.test.com'  
    mail_user = 'user'  
    mail_pass = 'pass'   
    sender = 'xxx@xx.com'  
    receivers = ['xxx@xx.com']  
    message = MIMEText(emailBody,'plain','utf-8')   
    message['Subject'] = '服务器巡查' 
    message['From'] = sender     
    message['To'] = receivers[0]  
    try:
        smtpObj = smtplib.SMTP() 
        smtpObj.connect(mail_host,25)
        smtpObj.login(mail_user,mail_pass) 
        smtpObj.sendmail(
            sender,receivers,message.as_string()) 
        smtpObj.quit() 
    except smtplib.SMTPException as e:
        print('error',e)

def scanPool(result_list):
    p = Pool(processes=8)
    p.map(scan,result_list)
    p.close
    p.join

def scan(server):
    a=scanIcmp(server['ip'])
    b=scanRemote(server['ip'],server['port'])
    c = int(a+b)
    if server["checkNum"] != c:
        ip='"{}"'.format(server['ip'])
        updateMysql('django.app01_serverinfo',c,ip)

def scanIcmp(ip):
    ip_id = randint(1,65535) 
    icmp_id = randint(1,65535)
    icmp_seq = randint(1,65535)
    packet = IP(dst=ip,ttl=64,id=ip_id)/ICMP(id=icmp_id,seq = icmp_seq)/b'rootkit'
    result = sr1(packet,timeout=1,verbose=False)
    if result:
        return 0
    else:
        return 1

def scanRemote(ip,port):
    packet = IP(dst=ip)/TCP(dport=int(port))
    result = sr1(packet,timeout=1,verbose=False)
    if result:
        if result[TCP].flags=='SA':
            return 0
        else:
            return 2
    else:
        return 2

def main():
    serverList=getServer()
    scanPool(serverList)
    emailBody=getEmailbody()
    if emailBody:
        sendMail(emailBody)

if __name__ == '__main__':
    main()
