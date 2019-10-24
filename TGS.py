#coding: utf-8
import sys
import datetime
import KEY

'''
Ticket Grant Server (TGS)
Two Responsibilities:
1. Generate TGT(Ticket Grant Ticket) with KDC secret key and TGS session key
2. Generate ST(Service Ticket) with Service secret key and Service session key
'''
class tgs():
    def __init__(self,TGS_name,secret_key,expire):
        self.TGS_name = TGS_name
        self.secret_key = secret_key
        self.expire = expire

'''
Generate ticket ,including TGT(Ticket Grant Ticket)and ST（Service Ticket）
TGT is the ticket to check the validation between client and KDC
ST is the ticket to check the validation between client and service requested
'''
    def genTicket(self,user,ip,timestamp,session_key,master_key):
        ticket1 = user + '#' + self.TGS_name + '#' +  timestamp + '#' + ip + '#' + self.expire + '#' + session_key  
        ticket2 = self.TGS_name + '#' + timestamp + '#' + self.expire + '#' + session_key
        aes1 = KEY.aescrypt(self.secret_key)
        ticket1 = aes1.encrypt(ticket1) # TGT encrypted with TGS secret key which client don't know
        aes2 = KEY.aescrypt(master_key) 
        ticket2 = aes2.encrypt(ticket2) # encrypted with client's master key which generates from client's password
        ticket = ticket1 + '#' + ticket2
        return ticket

'''
decrypt the service ticket with service secret key,
and then get the service session key from service ticket 
'''
def decrypt_service_ticket(info,service_secret_key):
    info0 = info.split('#')[0]
    info1 = info.split('#')[1]
    key = KEY.aescrypt(service_secret_key)
    info0 = key.decrypt(info0)
    service_session_key=info0.split('#')[5]
    key = KEY.aescrypt(service_session_key)
    info1 = key.decrypt(info1)
    print(info0 + '\n' + info1)
    if (valid_service_ticket(info0,info1)):
        return True
    else:
        return False


'''
check the information from two parts of service ticket if the same
and check if the ticket expired
'''
def valid_service_ticket(info0,info1):
    user0 = info0.split('#')[0]
    user1 = info1.split('#')[0]
    ts0 = info0.split('#')[2]
    ts1 = info1.split('#')[1]
    expire = info0.split('#')[4]
    #print(user0 + '\n' + user1)
    #print(ts0 + '\n' + ts1 + '\n' + expire)
    if ((user0 == user1) and (ts0 == ts1) and check_expire(ts0,expire)):
        return True
    else:
        return False

def check_expire(timestamp,expire):
    d = datetime.date.today()
    d1 = datetime.datetime.strptime(timestamp,'%Y-%m-%d')
    d1 = d1 + datetime.timedelta(days=int(expire))
    if(str(d1) > str(d)):
        return True
    else:
        return False



