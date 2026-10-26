"""Fixed disposable Runtime for process-authority tests; stdio is harness-only.

No model, provider, shell, arbitrary executable, network endpoint, or credentials.
The attack modes exercise fork/SCM_RIGHTS handoff of the SAME already-open socket.
"""
import array
import json
import os
import socket
import subprocess
import sys


def transmit(channel, command):
    if "hex" in command:
        data = bytes.fromhex(command["hex"])
    elif "raw" in command:
        data = command["raw"].encode()
    elif "size" in command:
        data = b"x" * command["size"]
    else:
        data = json.dumps(command["message"]).encode()
    ancillary = []
    if command.get("mode") == "rights":
        ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [channel.fileno()]))]
    channel.sendmsg([data], ancillary)
    print(json.dumps({"sent": True, "pid": os.getpid(), "uid": os.getuid()}), flush=True)
    result = json.loads(channel.recv(131072))
    print(json.dumps(result), flush=True)


def main():
    channel = socket.socket(fileno=int(sys.argv[1]))
    if len(sys.argv) > 2 and sys.argv[2] == "--receive-fd":
        data, ancillary, _, _ = channel.recvmsg(1, socket.CMSG_SPACE(4))
        descriptors = array.array("i")
        descriptors.frombytes(ancillary[0][2])
        channel.close()
        channel = socket.socket(fileno=descriptors[0])
        transmit(channel, json.loads(sys.stdin.readline()))
        return
    print(json.dumps({"ready": True, "pid": os.getpid(), "uid": os.getuid()}), flush=True)
    for line in sys.stdin:
        command = json.loads(line)
        if command.get("mode") == "exit":
            return
        if command.get("mode") == "fork":
            pid = os.fork()
            if pid == 0:
                try:
                    transmit(channel, command)
                finally:
                    os._exit(0)
            os.waitpid(pid, 0)
        elif command.get("mode") == "handoff":
            sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            process = subprocess.Popen([sys.executable, "-I", __file__, str(receiver.fileno()), "--receive-fd"],
                                       pass_fds=(receiver.fileno(),), stdin=subprocess.PIPE,
                                       stdout=sys.stdout, stderr=sys.stderr, text=True)
            receiver.close()
            sender.sendmsg([b"f"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [channel.fileno()]))])
            sender.close()
            process.communicate(json.dumps(command) + "\n", timeout=5)
            if process.returncode != 0:
                raise RuntimeError("handoff fixture failed")
        else:
            transmit(channel, command)


if __name__ == "__main__":
    main()
