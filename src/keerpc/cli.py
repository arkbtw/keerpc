import argparse
from asyncio import CancelledError
from getpass import getpass
from ipaddress import ip_address
import logging
from pathlib import Path
import sys
import weakref
from keerpc import KeerpcConn,create_kdblist
from aiohttp import web
from pykeepass import PyKeePass
from pykeepass.pykeepass import CredentialsError
import logging


logger=logging.getLogger(__name__)
socket_refs=weakref.WeakSet()
async def websocket_handler(request:web.Request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)

    socket_refs.add(ws)
    connection=KeerpcConn()
    connection.on_authenticate=lambda auth_code:print(f"Copy authentication code client: {auth_code}")
    logger.info("websocket connection start")
    async for msg in ws:
        if msg.type == web.WSMsgType.TEXT:
            if msg.data == 'close':
                await ws.close()
            else:
                response_msg=connection.handler(msg.data)
                await ws.send_str(response_msg)
        elif msg.type == web.WSMsgType.ERROR:
            print('ws connection closed with exception %s' %
                      ws.exception())

    if connection.session:
        print(f"Disconnected from {connection.session.name}.")
    logger.info('websocket connection closed')
    return ws

async def on_shutdown(app):
    for ws in socket_refs:
        await ws.close()


def port(port:str):
    i=int(port)
    if i<0 or i>0xffff:
        raise ValueError("Bad port number.")
    return i

def loglevel(l:str):
    integer=logging._nameToLevel.get(l)
    if integer is None:
        raise ValueError("Not a valid log level.")
    return integer

def enter_password(filename):
    p=f"Enter password for database {filename}:"
    try:
        passwd=getpass(prompt=p,echo_char="*")
        return PyKeePass(filename,passwd)
    except CredentialsError:
        print("Invalid credentials.")
        return enter_password(filename)
    except KeyboardInterrupt:
        print()
        exit(0)

def file(path:str):
    p=Path(path)
    if not p.is_file():
        raise ValueError("Not a valid file.")
    return str(p)


def main():
    try:
        parser=argparse.ArgumentParser(description="An implementation of keepassrpc server in python.")
        parser.add_argument("-a","--addr",type=ip_address,help="IP address.")
        parser.add_argument("-p","--port",type=port,help="IP address port.")
        parser.add_argument("-l","--log",type=loglevel,help="One of DEBUG,INFO,WARNING,ERROR or CRITICAL.")
        parser.add_argument("dbfile",help="One or more path to a keepass database file.",type=file,nargs="*")

        args=parser.parse_args()
        ip=args.addr if args.addr else ip_address("127.0.0.1")
        p=args.port if args.port else 12546
        logging.basicConfig(level=args.log,stream=sys.stdout) if args.log else None

        create_kdblist([enter_password(file) for file in args.dbfile])
        app = web.Application()
        app.add_routes([web.get("/", websocket_handler)])
        app.on_shutdown.append(on_shutdown)
        web.run_app(app,host=str(ip),port=p)
    except Exception as e:
        sys.exit(f"Exited with error {e}.")
