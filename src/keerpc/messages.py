FEATURES=["KPRPC_FEATURE_VERSION_1_6","KPRPC_SECURITY_FIX_20200729","KPRPC_GENERAL_CLIENTS"]
def proof_msg(server_proof:str):
    srp={"stage":"proofToClient","M2":server_proof,"securityLevel":2}
    msg={"protocol":"setup","srp":srp,"version":int.from_bytes(bytes([2,0,2]))}
    return msg

def identify_msg(server_ekey:str,salt:str,guid:str):
    srp={"stage":"identifyToClient","I":guid,"B":server_ekey,"s":salt,"securityLevel":2}
    features=FEATURES
    msg={"protocol":"setup","srp":srp,"version":int.from_bytes(bytes([2,0,2])),
         "features":features,
         "clientDisplayName":"keerpc",
         "clientDisplayDescription":"keepassRPC implementation in python",
         }
    return msg

def key_msg(guid:str,server_challenge:str):
    key={"username":guid,"securityLevel":2,"sc":server_challenge}
    features=FEATURES
    msg={"protocol":"setup","key":key,"version":int.from_bytes(bytes([2,0,2])),
         "features":features,
         "clientDisplayName":"keerpc",
         "clientDisplayDescription":"keepassRPC implementation in python",
         }
    return msg

def challange_msg(guid:str,server_response:str):
    key={"username":guid,"securityLevel":2,"sr":server_response}
    msg={"protocol":"setup","key":key,"version":int.from_bytes(bytes([2,0,2]))}
    return msg

def rpc_msg(data:str,iv:str,hmac:str):
    rpc={"message":data,"iv":iv,"hmac":hmac}
    msg={"protocol":"jsonrpc","jsonrpc":rpc,"version":int.from_bytes(bytes([2,0,2]))}
    return msg

def error_msg(err:str,code:str):
    e={"code":code,"messageParams":[err]}
    #msg={"protocol":"error","error":e,"version":int.from_bytes(bytes([2,0,2]))}
    msg={"protocol":"setup","error":e,"version":int.from_bytes(bytes([2,0,2]))}
    return msg
