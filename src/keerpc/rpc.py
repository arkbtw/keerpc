from dataclasses import dataclass,asdict
from pathlib import Path
import subprocess
from typing import Callable
from urllib.parse import urlparse
from enum import Enum
import json
from uuid import UUID
from jsonrpc import JSONRPCResponseManager,dispatcher
from jsonrpc.manager import JSONRPCRequest
from pykeepass import PyKeePass,Entry,Group
from pykeepass.kdbx_parsing import KDBX 
from dacite import from_dict
import string
import secrets
import pyotp
import re

dblist:list[PyKeePass]=[]

def save_remote(db:PyKeePass,transformed_key=None):
    db_bytes=KDBX.build(
        db.kdbx,
        password=db.password,
        keyfile=db.keyfile,
        transformed_key=transformed_key,
        decrypt=True
    )
    subprocess.run(["gio","save",db.filename],input=db_bytes,check=True)

def is_remote(filename:str):
    r=subprocess.run(["gio","info","-f",filename],capture_output=True)
    matches=re.findall(b"filesystem::remote: (TRUE|FALSE)",r.stdout)
    if matches and matches[0]==b"TRUE":
        return True
    return False

def save(db:PyKeePass):
    #use gio for remote gvfs files
    if is_remote(db.filename):
        save_remote(db)
    else:
        db.save()

def create_kdblist(db_list:list[PyKeePass]):
    global dblist
    if dblist:
        raise ValueError("cannot set dblist more than once")
    dblist=db_list


def mapall_dbs(func:Callable[[PyKeePass],list[Entry]]):
    for db in dblist:
        yield from ((db,e) for e in func(db))

@dispatcher.add_method
def GetAllDatabases():
    return [asdict(Database.fromdb(db)) for db in  dblist]

@dispatcher.add_method
def GetPasswordProfiles():
    return ["Short","Medium","Long"]

@dispatcher.add_method
def GeneratePassword(profile:str,url:str):
    ascii=string.printable.split(' ')[0]
    if profile=="Short":
        return ''.join(secrets.choice(ascii) for _ in range(12))
    elif profile=="Medium":
        return ''.join(secrets.choice(ascii) for _ in range(18))
    elif profile=="Long":
        return ''.join(secrets.choice(ascii) for _ in range(24))
    else:
        raise Exception("unknown password profile")


@dispatcher.add_method
def FindLogins(url:list[str],action_url:str,realm:str,search_type:LoginSearchType,full_match:bool,uuid:str,filename:str,freetext:str,username:str):
    if uuid:
        find=lambda db:db.find_entries(uuid=UUID(uuid))
        return [asdict(JEntry.fromdb_entry(e,db)) for db,e in mapall_dbs(find)]
    if freetext:
        match=f".*{freetext}.*"
        find=lambda db:db.find_entries(username=username if username else match,title=match,tags=match,regex=True,recursive=True)
        return [asdict(JEntry.fromdb_entry(e,db)) for db,e in mapall_dbs(find)]
    if len(url)>0:
        entries=[]
        for u in url:
            parsed=urlparse(u,scheme="http")
            host=f"{parsed.scheme}://{parsed.netloc}.*"
            find=lambda db:db.find_entries(username=username,url=parsed.geturl() if full_match else host,recursive=True,regex=True)
            entries.extend([asdict(JEntry.fromdb_entry(e,db)) for db,e in mapall_dbs(find)])
        return entries
    return []

@dispatcher.add_method
def AddLogin(entrydict,parent_uuid:str,filename:str):
    db=next((db for db in dblist if db.filename==filename),None)
    if db is None:
        db=dblist[0]
    group=db.root_group
    if parent_uuid:
        g=db.find_groups(uuid=UUID(parent_uuid),first=True)
        if g:
            group=g
    entry=from_dict(JEntry,entrydict)
    new_entry=db.add_entry(group,*entry.todb_args())
    save(db)
    return asdict(JEntry.fromdb_entry(new_entry,db))

@dispatcher.add_method
def UpdateLogin(entrydict,olduuid:str,urlMergMode:int,filename:str):
    db=next((db for db in dblist if db.filename==filename),None)
    if db is None:
        db=dblist[0]
    (title,username,password,url)=from_dict(JEntry,entrydict).todb_args()
    entry=db.find_entries(uuid=UUID(olduuid),first=True)
    if not entry:
        raise Exception("entry not found")
    if title:
        entry.title=title
    if username:
        entry.username=username
    if password:
        entry.password=password
    if url:
        entry.url=url
    save(db)
    return asdict(JEntry.fromdb_entry(entry,db))


def response(req:bytes):
    msg=json.loads(req)
    jreq=JSONRPCRequest.from_data(msg)
    return JSONRPCResponseManager.handle_request(jreq,dispatcher).json

@dataclass
class Database:
    name:str
    fileName:str
    icon:str
    root:JGroup
    active:bool
    @staticmethod
    def fromdb(db:PyKeePass):
        g:Group=db.root_group
        entries=[]
        for e in g.entries:
            entries.append(EntrySummary.fromdb_entry(e))
        groups=[]
        for e in g.subgroups:
            groups.append(JGroup.fromdb_group(e))
        root=JGroup(g.name,g.uuid.hex,g.icon,g.path,entries,groups)
        filename=db.filename if Path.is_file(db.filename) else str(dblist.index(db))
        return Database(db.database_name,db.filename,g.icon,root,True)


@dataclass
class JGroup:
    title:str
    uniqueID:str
    iconImageData:str
    path:str
    childLightEntries:list[EntrySummary]
    childGroups:list[JGroup]
    @staticmethod
    def fromdb_group(group:Group):
        entries=[]
        for entry in group.entries:
            entries.append(EntrySummary.fromdb_entry(entry))
        groups=[]
        for g in group.subgroups:
            groups.append(JGroup.fromdb_group(g))
        return JGroup(group.name,group.uuid.hex,group.icon,group.path,entries,groups)

@dataclass
class GroupSummary:
    title: str
    uniqueID: str
    iconImageData: str
    path: str
    @staticmethod
    def fromdb_group(group:Group):
        return GroupSummary(group.name,group.uuid.hex,group.icon,group.path)

@dataclass
class EntrySummary:
    iconImageData:str
    uRLs:list[str]
    uniqueID:str
    title:str
    usernameValue:str
    usernameName:str
    @staticmethod
    def fromdb_entry(entry:Entry):
        return EntrySummary(entry.icon,[entry.url],entry.uuid.hex,entry.title,'username',entry.username)

@dataclass
class Field:
    displayName:str
    name:str
    value:str
    id:str
    type:str
    page:int

class LoginSearchType(int,Enum):
    LSTall=0
    LSTnoForms=1
    LSTnoRealms=2

@dataclass
class JEntry:
    db:Database|None
    parent:GroupSummary|None
    iconImageData:str|None
    alwaysAutoFill:bool|None
    alwaysAutoSubmit: bool|None
    neverAutoFill: bool|None
    neverAutoSubmit: bool|None
    priority: int|None
    uRLs: list[str]|None
    matchAccuracy: int|None
    hTTPRealm: str|None
    uniqueID: str|None
    title: str|None
    formFieldList: list[Field]|None
    
    @staticmethod
    def fromdb_entry(entry:Entry,database:PyKeePass):
        db=Database.fromdb(database)
        g=GroupSummary.fromdb_group(entry.parentgroup)
        username=Field('username','username',entry.username,'username',"FFTusername",0)
        password=Field('password','password',entry.password,'password',"FFTpassword",0)
        fields=[username,password]
        if entry.otp:
            parsed=pyotp.parse_uri(entry.otp)
            otp=pyotp.TOTP(parsed.secret).now()
            fields.append(Field('otp','otp',otp,'otp',"FFTtext",0))
        e=JEntry(db,g,entry.icon,False,False,False,False,0,[entry.url],0,'',entry.uuid.hex,entry.title,fields)
        return e
    def todb_args(self):
        title=self.title
        username=None
        password=None
        url=None
        if self.formFieldList:
            username=next((f.value for f in self.formFieldList if f.type=="FFTusername"),None)
            password=next((f.value for f in self.formFieldList if f.type=="FFTpassword"),None)
        parsed=urlparse(self.uRLs[0],scheme="http") if self.uRLs else None
        url=f"{parsed.scheme}://{parsed.netloc}" if parsed else None
        return (title,username,password,url)
