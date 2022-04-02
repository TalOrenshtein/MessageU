__author__ = "Tal Orenshtein"
__date__ = '05/12/21'
import selectors 
import socket
import sqlite3
import struct
import uuid
from datetime import datetime
from respHdr import *
from reqHdr import *
serverVersion='2'
#defs
publicKeyLength=160
UUIDLength=16
nameMaxLength=255
def getPort():
    with open('port.info') as f:
        l=f.readlines()
        try:
            if len(l)==1 and (port:=int(l[0])) >= 0 and port<pow(2,16):
                return port
            else:
                raise Exception("Port must be a positive number and smaller than "+str(pow(2,16)+"."))
        except Exception:
            raise Exception('Bad file format.')
#Initzialize:
if __name__ == "__main__":
    db=sqlite3.connect('server.db')
    db.text_factory=bytes
    db.executescript("""
    CREATE TABLE IF NOT EXISTS clients(ID TEXT PRIMARY KEY,Name TEXT NOT NULL,
    PublicKey TEXT NOT NULL,LastSeen date
    );
    CREATE TABLE IF NOT EXISTS messages(ID integer PRIMARY KEY AUTOINCREMENT,ToClient TEXT NOT NULL 
    ,FromClient TEXT NOT NULL,Type TEXT NOT NULL,Content BLOB,FOREIGN KEY(ToClient) REFERENCES clients(id),FOREIGN KEY(FromClient) REFERENCES clients(id)
    )
    """)

sel = selectors.DefaultSelector()
def accept(sock, mask):
    conn, addr = sock.accept()
    conn.setblocking(False)
    sel.register(conn, selectors.EVENT_READ, processRequest)
#Processes the response and sends it to the client.
def sendResp(conn,resp):
    respStructFrmt="!1s H I" #contains: ver,code,payload_size
    if resp.payload_size>0:
        if(type(resp.payload)==type([]) or type(resp.payload)==type(())):
            #in case the payload is iterable
            for e in resp.payload:
                if type(e)==type(1):
                    respStructFrmt+=" I"
                else:
                    respStructFrmt+=" "+str(len(e))+"s"
        else:
            respStructFrmt+=" "+str(len(resp.payload))+"s"
    respLst=[]
    for e in resp.getTuple():
        if type(e)==type(b""):
            respLst.append(e)
        elif type(e)==type(uuid.UUID(int=0)):
            respLst.append(e.bytes)
        elif type(e)==type(1):
            respLst.append(e)
        else:
            respLst.append(bytes(e,'utf-8'))
    respData=struct.pack(respStructFrmt,*respLst)
    return conn.send(respData)
def updateLastSeen(req):
    cursor=db.cursor()
    cursor.execute("""
    UPDATE clients SET LastSeen=? WHERE ID=?
    """,(datetime.now(),req.clientID.bytes))
#Register the user with the requested name only if it's not already taken.
def handleReg(conn,req):
    resp=respHdr(serverVersion,0)
    cursor=db.cursor()
    #Checks if the name is already used
    cursor.execute("""
    SELECT Name FROM clients WHERE Name=?
    """,(req.payload[0],))
    if cursor.fetchone() is not None:
        #Name is already been used - send respErr(code 9000)
        resp.code=respErr
        sendResp(conn,resp)
    else:
        #generate UUID and send it with respSucReg (code 1000)
        newUid=uuid.uuid4()
        #Update the database.
        cursor.execute("""
        INSERT INTO clients VALUES(?,?,?,?)
        """,(newUid.bytes,req.payload[0],req.payload[1],datetime.now()))
        db.commit()
        #set the new UUID and send the response to the client.
        resp.payload=newUid.bytes
        resp.payload_size=UUIDLength
        resp.code=respSucReg
        sendResp(conn,resp)
#Iterates over all users except the one who requested the list and add them to the payload
def handleListReq(conn,req):
    updateLastSeen(req)
    resp=respHdr(serverVersion,0)
    cursor=db.cursor()
    cursor.execute("""
    SELECT ID,NAME FROM clients WHERE ID!=?
    """,(req.clientID.bytes,))
    cl=[]
    for e in cursor.fetchall():
        name=e[1].decode('utf-8')
        username=name+'\0'*(nameMaxLength-len(name))
        cl.append(struct.pack(str(UUIDLength)+'s '+str(nameMaxLength)+'s',e[0],bytes(username,'utf-8')))
        resp.payload_size+=(UUIDLength+nameMaxLength)
    resp.payload=cl
    resp.code=respList
    sendResp(conn,resp)
#Fetch all the messages sent to the user who requested his messages, format them following the protocol, adds them to the payload and deletes them from the database.
def handlePullMsgs(conn,req):
    updateLastSeen(req)
    resp=respHdr(serverVersion,0)
    cursor=db.cursor()
    cursor.execute("""
    SELECT * FROM messages WHERE ToClient=?
    """,(req.clientID.bytes,))
    #set the payload and payload_size.
    msgBuff=[]
    basicMsgFrmt='16s I 1s I' #follows the protocol - server's answer without the content.
    msgBuffFrmt="!" #making sure it'll use big endian order.
    #iterating user's incoming header messages and processing them.
    for e in cursor.fetchall():
        #e looks like (id,to,from,type,content)
        msgID=0;fromClient=2;msgType=3;content=4
        msgBuffFrmt+=basicMsgFrmt+" "
        if e[-1] is not None:
            msgBuffFrmt+=str(len(e[-1]))+"s "
        msgBuff.append(e[fromClient])
        msgBuff.append(e[msgID])
        msgBuff.append(e[msgType])
        if e[-1] is not None:
            msgBuff.append(len(e[content]))
            msgBuff.append(e[content])
        else:
            msgBuff.append(0) #if there's no message,0 is length of the message.
    if msgBuffFrmt!="!":    
        buff=struct.pack(msgBuffFrmt,*msgBuff)
        resp.payload_size=struct.calcsize(msgBuffFrmt)
        resp.payload=buff
    resp.code=respPullMsgs
    #deleting the messages that we sent to the client from the database.
    if sendResp(conn,resp):
        cursor.execute("""
        DELETE FROM messages WHERE ToClient=?
        """,(req.clientID.bytes,))
        db.commit()
#Fetch the requested public key and add it to the payload.
def handlePullPubKey(conn,req):
    updateLastSeen(req)
    resp=respHdr(serverVersion,0)
    cursor=db.cursor()
    cursor.execute("""
    SELECT PublicKey FROM clients where ID=?
    """,(req.payload,))
    if (pubKey:=cursor.fetchone())==None:
        #No user with the requested ID exists.
        resp.code=respErr
        sendResp(conn,resp)
        return
    else:
        #fetchone() returns a tuple or none, so we take the only element in that tuple, the public key.
        pubKey=pubKey[0]
    resp.payload=(req.payload,pubKey)
    resp.payload_size=sum([len(e) for e in resp.payload])
    resp.code=respPubKey
    sendResp(conn,resp)
#Stores the message received from the client at the database and adds the message id to the payload.
def handleSendMsg(conn,req):
    toClient=0;msgType=1;contentSize=2;content=3
    resp=respHdr(serverVersion,0)
    cursor=db.cursor()
    cursor.execute("""
    INSERT INTO messages (ToClient,FromClient,Type,Content) VALUES (?,?,?,?)
    """,(req.payload[toClient],req.clientID.bytes,req.payload[msgType],req.payload[content] if req.payload[contentSize]>0 else None))
    db.commit()
    resp.code=respSucMsg
    #following the protocol here, but what happens when lastrowid is larger than 2^32-1 ?
    resp.payload=(req.payload[toClient],cursor.lastrowid)
    resp.payload_size=len(req.payload[toClient])+struct.calcsize("I") #lastrowid is unsigned integer so we need to add those 4 bytes (struct.calcsize("I") returns the amount of space an unsigned int takes in a struct, and because it stores it "raw"- without python's int class wrapper, that value is 4) to the payload size.
    sendResp(conn,resp)
#receives the request, processes it and passing it to further processing.
def processRequest(conn, mask):
    reqHdrStruct=struct.Struct("!16s 1s 1s I")
    data = conn.recv(struct.calcsize(reqHdrStruct.format))
    if data:
        dataList=[]
        #following the protocol and processing the data received.
        dataTup=reqHdrStruct.unpack(data)
        dataList.append(uuid.UUID(bytes=dataTup[0]))
        dataList.append(dataTup[1].decode('utf-8'))
        dataList.append(dataTup[2].decode('utf-8'))
        dataList.append(dataTup[3])
        req=reqHdr(*dataList)
        if req.payload_size>0:
            pldata=conn.recv(req.payload_size)
            if not pldata:
                resp=respHdr(serverVersion,0,respErr)
                sendResp(conn,resp)
                sel.unregister(conn)
                conn.close()
                return
            if req.code==reqReg:
                payloadBytes=struct.unpack(str(nameMaxLength)+"s "+str(publicKeyLength)+"s",pldata) #sturct's format follows the protocol.
                req.payload=[str(payloadBytes[0],'utf-8').strip('\0'),payloadBytes[1]]
                handleReg(conn,req)
            if req.code==reqPubKey:
                req.payload=pldata
                handlePullPubKey(conn,req)
            if req.code==reqSendMsg:
                msgStructFrmt="!16s 1s I"
                 #unpacking without the message content,so we can receive the content using the message size received.
                msgHdr=struct.unpack(msgStructFrmt,pldata[0:struct.calcsize(msgStructFrmt)])
                if msgHdr[-1]>0:
                    msgStructFrmt+=" "+str(msgHdr[-1])+"s"
                req.payload=struct.unpack(msgStructFrmt,pldata)
                handleSendMsg(conn,req)
        elif req.code==reqList:
            handleListReq(conn,req)
        elif req.code==reqPullMsgs:
            handlePullMsgs(conn,req)
    else :
        sel.unregister(conn)
        conn.close()
sock = socket.socket()
sock.bind(('localhost', getPort()))
sock.listen()
sock.setblocking(False)
sel.register(sock, selectors.EVENT_READ, accept)
while True:
    events = sel.select()
    for key, mask in events:
        callback = key.data
        callback(key.fileobj, mask)