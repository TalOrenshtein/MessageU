#codes:
respSucReg=1000
respList=1001
respPubKey=1002
respSucMsg=1003
respPullMsgs=1004
respErr=9000

class respHdr:
    def __init__(self,ver,code,payloadSize=0,payload=None):
        self.version=ver
        self.code=code
        self.payload_size=payloadSize
        self.payload=payload
    def getTuple(self):
        lst=[self.version,self.code,self.payload_size]
        if self.payload_size>0:
            if(type(self.payload)==type([]) or type(self.payload)==type(())):
                for e in self.payload:
                    lst.append(e)
            else:
                lst.append(self.payload)
        return tuple(lst)