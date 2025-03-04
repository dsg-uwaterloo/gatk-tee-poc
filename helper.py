import os
import shutil
import pathlib

# create directories that don't already exist
def create_dirs(dirs):
    for dir in dirs:
        if not os.path.exists(dir):
            os.mkdir(dir)

# remove existing directories that are not the current directory
def remove_dirs(dirs):
    cwd = os.getcwd()
    for dir in dirs:
        if os.path.exists(dir) and os.path.abspath(dir) != cwd:
            shutil.rmtree(pathlib.Path(dir))

# sends the length of the message followed by the message
def send_message(socket, message):
    socket.send(len(message).to_bytes(4, byteorder='big'))
    socket.sendall(message)
    return

# receives the length of the message followed by the message
def receive_message(socket):
    message_size = int.from_bytes(socket.recv(4), byteorder='big')
    return socket.recv(message_size)