#codes:
reqReg=chr(100)
reqList=chr(101)
reqPubKey=chr(102)
reqSendMsg=chr(103)
reqPullMsgs=chr(104)
class reqHdr:
    def __init__(self,CID,cv,code,payloadSize,payload=None):
        self.clientID=CID
        self.version=cv
        self.code=code
        self.payload_size=payloadSize
        self.payload=payload