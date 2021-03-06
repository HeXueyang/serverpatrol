#!/usr/local/bin/python3
import pymysql,smtplib
from email.mime.text import MIMEText
from scapy.all import *
from random import randint
from multiprocessing import Pool
from pymysql.constants import CLIENT
host,user,password,port='172.17.0.1','root','root',3306

def getMysql(col,tablesName,item=None):
    mysql = pymysql.connect (host=host, user=user, password=password, port=port,charset='utf8')
    cursor = mysql.cursor()
    sql = "select {} from {} {};".format(col,tablesName,item)
    cursor.execute(sql)
    results = cursor.fetchall()
    cursor.close()
    mysql.close()
    return results

def updateMysql(updateValue):
    if updateValue and "update" in updateValue:
        mysql = pymysql.connect (host=host, user=user, password=password, port=port,charset='utf8',client_flag=CLIENT.MULTI_STATEMENTS)
        cursor = mysql.cursor()
        sql = updateValue
        cursor.execute(sql)
        mysql.commit()
        cursor.close()
        mysql.close()

def mysqlWhere(messList):
    while [] in messList:
        messList.remove([])
    if messList:
        updateValue=""
        for i in messList:
            ip='"{}"'.format(i[0])
            updateValue+='update django.app01_serverinfo set checkNum={} where ip={};'.format(i[1],ip)
        return updateValue
    else:
        return messList

def getServer():
    results=getMysql('ip,os,checkNum','django.app01_serverinfo')
    serverList=[]
    for i in results:
        if i[1] == 1:
            serverList.append({"ip":i[0],"port":"3389","checkNum":i[2]})
        if i[1] == 2:
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
    res = p.map(scan,result_list)
    p.close
    p.join
    return res

def scan(server):
    b=0
    a=scanIcmp(server['ip'])
    if server['port'] == "3389" or server['port'] == "22" :
        b=scanRemote(server['ip'],server['port'])
    c = int(a+b)
    messList=[]
    if server["checkNum"] != c:
        messList=[server['ip'],c]
    return messList

def scanIcmp(ip):
    ip_id = randint(1,65535) 
    icmp_id = randint(1,65535)
    icmp_seq = randint(1,65535)
    packet = IP(dst=ip,ttl=64,id=ip_id)/ICMP(id=icmp_id,seq = icmp_seq)/b'rootkit'
    result = sr1(packet,timeout=1,verbose=False)
    if result:
        return 0
    return 1

def scanRemote(ip,port):
    packet = IP(dst=ip)/TCP(dport=int(port))
    result = sr1(packet,timeout=1,verbose=False)
    if result:
        if result[TCP].flags=='SA':
            return 0    
    return 2

def main():
    serverList=getServer()
    res = scanPool(serverList)
    updateValue = mysqlWhere(res)
    updateMysql(updateValue)
    emailBody=getEmailbody()
    if emailBody:
        sendMail(emailBody)

if __name__ == '__main__':
    main()
