import socket
import datetime
import KEY
import TGS

'''
Key Distributed Center(KDC) is responsible for dealing with the authentication between clients and servers

'''
def socket_service_data():
    TGS_name = 'TGS_test'
    expire = 30
    now = datetime.date.today()
    TGS_session_key = KEY.TGS_sessionkey()
    service_secret_key = ''
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('127.0.0.1', 6666))  # local IP and Port
        # s.bind(('192.168.20.1', 6666))  #Server IP and Port
        s.listen(10)
    except socket.error as msg:
        print(msg)
        sys.exit(1)

    print("Wait for Connection..................")
    while True:
        sock, addr = s.accept()
        buf = sock.recv(1024)  #receive message
        buf = buf.decode()  #decode message
        #print(str(buf))
        info = str(buf).split('#',1)[1]
        sign = str(buf).split('#',1)[0]
        if (sign == 'A'):
            user = info
            print("The User request from " + str(addr[0]) + " is:  " + user)
            print('Checking user [' + user +'] is legal...')
            if (isuserexist(user)):
                print('User is legal!')
                TGS_secret_key = KEY.TGS_sessionkey()
                user_master_key = KEY.User_masterkey('password') # if user is legal,get user's master key
                print('User [' + user + ']\'s master key is: ' + user_master_key)
                print('TGS session key is: ' + TGS_session_key)
                print('TGS secret key is: '+TGS_secret_key)
                print('The current time is: ' + str(now))
                tgs = TGS.tgs(TGS_name,TGS_secret_key,str(expire))
                tgt = tgs.genTicket(user,str(addr[0]),str(now),TGS_session_key,user_master_key)
                sock.send(('1#' + tgt).encode())
            else:
                print('User is illegal!')
                res = 'User [' + user + '] is illegal!'
                sock.send(('2#' + res).encode())
        # return buf
        # sock.close()
        elif (sign == 'B'): 
            response,user,flag = check_tgt(info,TGS_secret_key)
            print(response)
            st =''
            if(flag):
                service_secret_key = KEY.getservice_secret_key(info.split('#')[1]) # Get the secret key of service which client requests
                service_session_key = KEY.TGS_sessionkey()
                print('Service secret key is: ' + service_secret_key)
                print('Service session key is: '+service_session_key)
                print('TGS session key is: '+ TGS_session_key)
                tgs = TGS.tgs(info.split('#')[1],service_secret_key,str(expire))
                st = tgs.genTicket(user,str(addr[0]),str(now),service_session_key,TGS_session_key)    
            sock.send(response.encode())
            if(st.find('#') >= 0):
                sock.send(st.encode())
        elif (sign == 'C'):
            if (TGS.decrypt_service_ticket(info,service_secret_key)):
                print('Service Ticket valid')
            else:
                print('Service Ticket invalid')

def isuserexist(user):
    if (user == 'guowei'):
        return True
    else:
        return False

#Check the service request from user if valid
def check_tgt(info,TGS_secret_key):
    response = ''
    flag = False
    user = ''
    tgt0 = info.split('#')[0]
    service_name = info.split('#')[1]
    tgt1 = info.split('#')[2]
    if check_service_exist(service_name):
        key = KEY.aescrypt(TGS_secret_key)
        tgt0 = key.decrypt(tgt0)
        session_key = tgt0.split('#')[5]
        key1 = KEY.aescrypt(session_key)
        tgt1 = key1.decrypt(tgt1)
        print(tgt0 + '\n' + tgt1)
        response,user,flag = check_info_valid(tgt0,tgt1)
    else:
        response = '3# [-] The service you request does not exist.'
    return response,user,flag

#Check the service requested from user if exist
def check_service_exist(service_name):
    if (service_name == 'test'):
        return True
    else:
        return False

'''Check the TGT infomation decrypted by TGS's secret key 
if the same as request infomation from user decrypted 
by sessionkey'''
def check_info_valid(tgt0,tgt1):
    checkinfo = ''
    flag = False
    user = ''
    if(tgt0.split('#')[0] == tgt1.split('#')[0]): #Check the user if the same
        if(tgt0.split('#')[2] == tgt1.split('#')[1]):
            if(TGS.check_expire(tgt0.split('#')[2],tgt0.split('#')[4])):
               checkinfo = '[+] request information is valid.'
               user = tgt0.split('#')[0]
               flag = True
            else:
               checkinfo = '4# [-] Out of expiration, please request again.'
        else:
            checkinfo = '5# [-] Service request date is not the same.'
    else:
        checkinfo = '6# [-] Service request user is not the same.'
    return checkinfo,user,flag


if __name__ == '__main__':
    socket_service_data()
