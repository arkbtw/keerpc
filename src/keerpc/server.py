from base64 import b64decode, b64encode
from hashlib import sha1, sha256
from uuid import UUID
from Cryptodome.Util.Padding import pad, unpad
from dataclasses import dataclass
from Crypto.Cipher import AES
from platformdirs import PlatformDirs
import json
import secrets
import string
import keerpc.messages as messages
import keerpc.rpc as rpc
import sqlite3
import logging

@dataclass
class Proofs:
    server:bytes
    client:bytes
@dataclass
class Session:
    name:str
    username:str
    key:bytes
@dataclass
class Client:
    username:str
    display_name:str
    key:int
    challange:bytes=secrets.token_bytes(32)
    proofs:Proofs|None=None
@dataclass
class KeerpcConn:
    session:Session|None=None
    _new_client:Client|None=None

    def handler(self,json_msg:str):
        logger.debug(f"request:{json_msg}")
        jmsg=json.loads(json_msg)
        #return json.dumps(handle_msg(jmsg,self))
        try:
            response=handle_msg(jmsg,self)
            logger.debug(f"response:{response}")
            return json.dumps(response)
        except Exception as err:
            session=self.session 
            if session is not None:
                self.session=None
                _=clientsdb.execute("DELETE FROM clients WHERE id=?",[session.username])
                clientsdb.commit()
            response=messages.error_msg("setup error","AUTH_FAILED")
            logger.error(err)
            logger.debug(f"response:{response}")
            return json.dumps(response)

    def on_authenticate(self,auth_code:str):
        pass

logger=logging.getLogger(__name__)
datadir=PlatformDirs("keerpc","Author",ensure_exists=True).user_data_path
clientsdb=sqlite3.connect(datadir/"appdata.db")
_=clientsdb.execute("CREATE TABLE IF NOT EXISTS clients(id PRIMARY KEY,key)")
clientsdb.commit()

SPRIME=0xd4c7f8a2b32c11b8fba9581ec4ba4f1b04215642ef7355e37c0fc0443ef756ea2c6b8eeb755a1c723027663caa265ef785b8ff6a9b35227a52d86633dbdfca43
G=2
GUID="969a1f05-f24a-4baa-a3f6-5da17a9e05a8"


def handle_msg(jmsg,conn:KeerpcConn):
    new_client=conn._new_client
    conn._new_client=None

    if jmsg['protocol']=="setup":
        if jmsg.get('srp'):
            if jmsg['srp']['stage']=='proofToServer':
                proof=jmsg['srp']['M']
                proofs=new_client.proofs if new_client else None
                if new_client is None or proofs is None or not secrets.compare_digest(proofs.client,bytes.fromhex(proof)):
                    raise Exception("key mismatch")

                addclient(new_client.username,hex(new_client.key)[2:])
                key=sha256(f"{new_client.key:X}".encode()).digest()
                conn.session=Session(new_client.display_name,new_client.username,key)
                print(f"Connected to {conn.session.name}.")
                logging.info(f"session started for client {new_client.username}")
                return messages.proof_msg(proofs.server.hex())

            client_id=jmsg['srp']['I']
            client_ekey=int(jmsg['srp']['A'],16)
            name=jmsg['clientDisplayName']
            password,salt=gen_password()
            server_ekey,session_key=derive_keys(password,salt,client_ekey)
            username=UUID(client_id).hex

            conn._new_client=Client(username,name,session_key)
            conn._new_client.proofs=derive_proofs(client_ekey,server_ekey,session_key)
            conn.on_authenticate(password)
            return messages.identify_msg(f"{server_ekey:X}",salt.hex(),GUID)

        if jmsg.get('key'):
            if jmsg['key'].get('cr') and jmsg['key'].get('cc'):
                cc=jmsg['key']['cc']
                cr=jmsg['key']['cr']
                if new_client is None:
                    raise Exception("client info not available")

                key=sha256(f"{new_client.key:X}".encode()).digest()
                client_response=sha256(f"1{key.hex()}{new_client.challange.hex()}{cc}".encode()).digest()
                if not secrets.compare_digest(bytes.fromhex(cr),client_response):
                    raise Exception("challange failed")

                conn.session=Session(new_client.display_name,new_client.username,key)
                print(f"Connected to {conn.session.name}.")
                logging.info(f"session started for client {new_client.username}")
                server_response=sha256(f"0{key.hex()}{new_client.challange.hex()}{cc}".encode()).hexdigest()
                return messages.challange_msg(GUID,server_response)

            username=UUID(jmsg['key']['username']).hex
            name=jmsg['clientDisplayName']

            key=clientsdb.execute("SELECT key FROM clients WHERE id=?",[username]).fetchone()
            if not key:
                raise Exception("key not found")

            conn._new_client=Client(username,name,int(key[0],16))
            return messages.key_msg(GUID,conn._new_client.challange.hex())

    if jmsg['protocol']=="jsonrpc":
        iv=b64decode(jmsg['jsonrpc']['iv'])
        client_hmac=b64decode(jmsg['jsonrpc']['hmac'])
        message=b64decode(jmsg['jsonrpc']['message'])
        if conn.session is None:
            raise Exception("session key not available")
        if verify_hmac(client_hmac,conn.session.key,message,iv):
            raise Exception("message authentication failed")

        aes_decrypt=AES.new(conn.session.key,AES.MODE_CBC,iv)
        decrypted=unpad(aes_decrypt.decrypt(message),AES.block_size)
        response=rpc.response(decrypted)

        aes=AES.new(conn.session.key,AES.MODE_CBC)
        encrypted=aes.encrypt(pad(response.encode(),AES.block_size))
        hmac=sha1(b''.join([sha1(conn.session.key).digest(),encrypted,aes.IV])).digest()

        siv=b64encode(aes.IV).decode()
        server_hmac=b64encode(hmac).decode()
        msg=b64encode(encrypted).decode()
        return messages.rpc_msg(msg,siv,server_hmac)
    raise Exception("protocol error")

def addclient(id:str,hexkey:str):
        _=clientsdb.execute("DELETE FROM clients WHERE id=?",[id])
        _=clientsdb.execute("INSERT into clients VALUES(?,?)",[id,hexkey])
        clientsdb.commit()

def verify_hmac(client_hmac:bytes,key:bytes,message:bytes,iv:bytes):
        hmac_input=b''.join([sha1(key).digest(),message,iv])
        hmac=sha1(hmac_input).digest()
        return not secrets.compare_digest(client_hmac,hmac)


def gen_password():
        salt=secrets.token_bytes(32)
        alphabet = string.ascii_letters + string.digits
        password = ''.join(secrets.choice(alphabet) for _ in range(4))
        return password,salt

def derive_privatekey(password:str,salt:bytes):
        ps=f"{salt.hex()}{password}".encode()
        phash=int.from_bytes(sha256(ps).digest())
        vkey=pow(G,phash,SPRIME)
        return vkey

def derive_ekey(private_key:int):
        secret=int.from_bytes(secrets.token_bytes(32))
        b=b''.join([SPRIME.to_bytes(64),G.to_bytes(64)])
        HMUL=int.from_bytes(sha1(b).digest())
        server_ekey=HMUL*private_key+pow(G,secret,SPRIME)
        while server_ekey%SPRIME==0:
            secret=int.from_bytes(secrets.token_bytes(32))
            server_ekey=HMUL*private_key+pow(G,secret,SPRIME)
        return secret,server_ekey

def derive_keys(password:str,salt:bytes,client_ekey:int):
    if client_ekey%SPRIME==0:
        raise Exception("bad client secret")
    private_key=derive_privatekey(password,salt)
    secret,server_ekey=derive_ekey(private_key)
    cs=f"{client_ekey:X}{server_ekey:X}".encode()
    hash_cs=int.from_bytes(sha256(cs).digest())
    Avu=client_ekey*(pow(private_key,hash_cs,SPRIME))
    session_key=pow(Avu,secret,SPRIME)
    return server_ekey,session_key

def derive_proofs(client_ekey:int,server_ekey:int,session_key:int):
    css=f"{client_ekey:X}{server_ekey:X}{session_key:X}".encode()
    client=sha256(css).digest()
    ams=f"{client_ekey:X}{client.hex()}{session_key:X}".encode()
    server=sha256(ams).digest()
    return Proofs(server,client)
