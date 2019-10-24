#encoding: utf8
import sys
import socket
import KEY
import time
from Crypto.Hash import SHA256

reload(sys)
sys.setdefaultencoding('utf8')

'''
模拟kerberos协议的客户端请求
接收并处理KDC发送过来的TGT和ST

'''
def sock_client_data():
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(('127.0.0.1', 6666))  #本地进行，所以IP为本地地址，如果服务端部署在其他地方，需要修改IP地址
            user = raw_input("input your name: ") # 模拟请求，发送请求用户信息
            data = user
            s.send(('A#' + data).encode())
            buf = s.recv(1024)
            buf = buf.decode()
            flag = str(buf).split('#',1)[0]
            if (flag == str(1)):
                s1 = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                s1.connect(('127.0.0.1',6666))
                TGT = str(buf).split('#',1)[1]
                print('The TGT from KDC is: ' + TGT)
                print('Ready to decrypt TGT...')
                Flag1 = True
                while Flag1:
                    password = raw_input('Input your password: ')
                    master_key = KEY.User_masterkey(password)
                    key = KEY.aescrypt(master_key)
                    TGT1 = key.decrypt(TGT.split('#')[1])
                    TGT0 = TGT.split('#')[0]
                    if TGT1.find('#') == -1:
                        Flag1 = True
                        print('Decryped wrong , please check your password!')
                    else:
                        Flag1 = False
                        print('Decrypted TGT is: ' + TGT1)
                session_key = TGT1.split('#')[3]
                service_name = raw_input('Please input the service name you request:')
                request = request_service_ticket(TGT0,TGT1,service_name,user) # send ST request
                s1.send(request.encode())
                response = s1.recv(1024)
                response = response.decode()
                if response.find('#') == -1:
                    print(response)
                else:
                    print(response)
                    print(sys.exit(1))
                st = s1.recv(1024)
                st = st.decode()
                print('Service Ticket from KDC: ' + st)
                st0 = st.split('#')[0]
                st1 = st.split('#')[1]
                service_request = request_service(user,st0,st1,session_key)
                s2 = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                s2.connect(('127.0.0.1',6666))
                s2.send(service_request.encode())
                time.sleep(10)
                s2.close()
            else:
                print(str(buf))
        except socket.error as msg:
            print(msg)
            print(sys.exit(1))
        s1.close()
        s.close()

'''
使用请求用户的master key解密KDC发过来的加密消息获取TGS的session key
利用TGS的session key加密请求信息，并与TGT（TGT是使用TGS的secret key加密，用户无法解密）一起返回给KDC

'''
def request_service_ticket(TGT0,TGT1,service_name,user):
    request1 = TGT0 + '#' +service_name
    session_key = TGT1.split('#')[3]
    timestamp = TGT1.split('#')[1]
    key = KEY.aescrypt(session_key)
    request2 = key.encrypt(user + '#' +timestamp)
    request = request1 + '#' + request2
    return 'B#' + request

'''
使用之前已经或得到的TGS session key解密TGS返回的消息，获取到service session key
向服务端请求时使用这个service session key加密请求信息，并连同ST（使用service secret key加密，用户无法解密）
发送到需要请求访问的service

'''
def request_service(user,st0,st1,TGS_sessionkey):
    key = KEY.aescrypt(TGS_sessionkey)
    request1 = key.decrypt(st1)
    service_session_key = request1.split('#')[3]
    timestamp = request1.split('#')[1]
    key1 = KEY.aescrypt(service_session_key)
    request = key1.encrypt(user + '#' + timestamp)
    return 'C#' + st0 + '#' + request




#def masterkey(password):
#    sha = SHA256.new()
#    sha.update(password)
#    return sha.hexdigest()[0:16]

if __name__ == '__main__':
    print('Sending request to KDC...')
    sock_client_data()
    #password = KEY.User_masterkey('password')
    #session_key = KEY.TGS_sessionkey()
    #print(password)
    #print(session_key)
    #aes = KEY.aescrypt(password)
    #e = aes.encrypt('guowei')
    #print(e)

