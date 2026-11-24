#!/usr/bin/env python3
# vmrun.py — run a command on the analysis VM (192.168.8.132) via paramiko.
# Usage:
#   python vmrun.py run "<cmd>"
#   python vmrun.py put <localfile> <remote>
#   python vmrun.py get <remote> <localfile>
import sys, os
import paramiko
HOST='192.168.8.132'; USER='mare'; PWD='Passw0rd!'

def connect():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PWD, timeout=20)
    return c

def main():
    cmd = sys.argv[1]
    c = connect()
    try:
        if cmd == 'run':
            _, out, err = c.exec_command(sys.argv[2], timeout=180)
            sys.stdout.write(out.read().decode('utf-8','replace'))
            e = err.read().decode('utf-8','replace')
            if e: sys.stderr.write(e)
            sys.exit(out.channel.recv_exit_status())
        elif cmd == 'put':
            sftp = c.open_sftp()
            sftp.put(sys.argv[2], sys.argv[3])
            print("put ok", sys.argv[2], "->", sys.argv[3])
        elif cmd == 'get':
            sftp = c.open_sftp()
            sftp.get(sys.argv[2], sys.argv[3])
            print("get ok")
        else:
            print("unknown", cmd); sys.exit(2)
    finally:
        c.close()

if __name__ == '__main__':
    main()
