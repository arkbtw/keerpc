from base64 import b64decode, b64encode
from hashlib import sha1, sha256
import json
import pickle
import secrets
import shutil
import unittest
from Crypto.Cipher import AES
from Cryptodome.Util.Padding import unpad
from keerpc.server import SPRIME,G, Session,derive_keys,KeerpcConn,handle_msg, pad
from keerpc.rpc import response,dblist,save_remote
from pykeepass import PyKeePass
import keerpc.messages as messages

class SRPtests(unittest.TestCase):
    def test_auth(self):
        password,salt="afkl",secrets.token_bytes(32)
        client_secret=int.from_bytes(secrets.token_bytes(32))
        client_ekey=pow(G,client_secret,SPRIME)
        while client_ekey%SPRIME==0:
            client_secret=int.from_bytes(secrets.token_bytes(32))
            client_ekey=pow(G,client_secret,SPRIME)
        server_ekey,sessionkey=derive_keys(password,salt,client_ekey)
        expect_key=client_authenticate(password,salt,server_ekey,client_secret,client_ekey)
        self.assertEqual(sessionkey,expect_key)

    def test_rpc_mode(self):
        msg='{"jsonrpc":"2.0","params":null,"method":"GetPasswordProfiles","id":3}'
        skey=secrets.token_bytes(32)
        aes=AES.new(skey,AES.MODE_CBC)
        encrypted=aes.encrypt(pad(msg.encode(),AES.block_size))
        hmac=sha1(b''.join([sha1(skey).digest(),encrypted,aes.IV])).digest()
        siv=b64encode(aes.IV).decode()
        hmac=b64encode(hmac).decode()
        data=b64encode(encrypted).decode()
        req=messages.rpc_msg(data,siv,hmac)
        conn=KeerpcConn()
        conn.session=Session("testuser","testid",skey)
        res=handle_msg(req,conn)
        res_msg=b64decode(res['jsonrpc']['message'])
        res_iv=b64decode(res['jsonrpc']['iv'])
        res_hmac=b64decode(res['jsonrpc']['hmac'])
        hmac=sha1(b''.join([sha1(conn.session.key).digest(),res_msg,res_iv])).digest()
        self.assertEqual(res_hmac,hmac)
        aes_decrypt=AES.new(conn.session.key,AES.MODE_CBC,res_iv)
        decrypted=unpad(aes_decrypt.decrypt(res_msg),AES.block_size)
        expect='{"result": ["Short", "Medium", "Long"], "id": 3, "jsonrpc": "2.0"}'.encode()
        self.assertEqual(decrypted,expect)

with open("tests/testdata.pkl","rb") as f:
    DATA=pickle.load(f)
class RPCtests(unittest.TestCase):
    def test_addlogin(self):
        shutil.copy("tests/testdb.kdbx","tests/testdb_copy.kdbx")
        db=PyKeePass("tests/testdb_copy.kdbx","demopass")
        dblist.clear()
        dblist.append(db)
        r=response(DATA.AddLogin.req)
        dblist.remove(db)
        result=json.loads(r)
        result['result']['db']=None
        result['result']['uniqueID']=None
        DATA.AddLogin.res['result']['db']=None
        DATA.AddLogin.res['result']['uniqueID']=None
        self.maxDiff=None
        self.assertEqual(DATA.AddLogin.res,result)
    def test_updatelogin(self):
        shutil.copy("tests/testdb.kdbx","tests/testdb_copy.kdbx")
        db=PyKeePass("tests/testdb_copy.kdbx","demopass")
        dblist.clear()
        dblist.append(db)
        r=response(DATA.UpdateLogin.req)
        dblist.remove(db)
        self.maxDiff=None
        result=json.loads(r)
        self.assertEqual(DATA.UpdateLogin.res,result)
    def test_findlogins(self):
        db=PyKeePass("tests/testdb.kdbx","demopass")
        dblist.clear()
        dblist.append(db)
        result=response(DATA.FindLogins.req)
        dblist.remove(db)
        self.maxDiff=None
        self.assertEqual(json.loads(result),DATA.FindLogins.res)
    def test_remote_save(self):
        shutil.copy("tests/testdb.kdbx","tests/testdb_copy.kdbx")
        db=PyKeePass("tests/testdb_copy.kdbx","demopass")
        entry=db.add_entry(db.root_group,"test title","user","pass","url")
        uid=entry.uuid
        save_remote(db)
        db=PyKeePass("tests/testdb_copy.kdbx","demopass")
        entry=db.find_entries(title="test title",first=True)
        self.assertEqual(entry.uuid,uid)
        


def client_authenticate(password:str,salt:bytes,server_ekey:int,client_secret:int,client_ekey:int):
    cs=int.from_bytes(sha256(f"{client_ekey:X}{server_ekey:X}".encode()).digest())
    phash=int.from_bytes(sha256(f"{salt.hex()}{password}".encode()).digest())
    b=b''.join([SPRIME.to_bytes(64),G.to_bytes(64)])
    HMUL=int.from_bytes(sha1(b).digest())
    base=server_ekey-HMUL*pow(G,phash,SPRIME)
    exp=client_secret+cs*phash
    sessionkey=pow(base,exp,SPRIME)
    return sessionkey

