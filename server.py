import argparse
import os
import subprocess
import sys
import shutil
import pathlib

import boto3

from ssl import *
from socket import *

# sends the length of the message followed by the message
def sendMessage(socket, message):
    socket.send(len(message).to_bytes(4, byteorder='big'))
    socket.sendall(message)
    return

# receives the length of the message followed by the message
def receiveMessage(socket):
    message_size = int.from_bytes(socket.recv(4), byteorder='big')
    return socket.recv(message_size)

# generate the private key for ssl
def generate_private_key(key_path):
  if not os.path.exists(key_path):
    subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-out", key_path])
  return

# generate self-signed certificate for ssl using the private key
def generate_self_signed_cert(key_path, cert_path, common_name):
  if not os.path.exists(cert_path):
    subprocess.run(["openssl", "req", "-new", "-x509", "-key", key_path, "-out", cert_path, "-subj", "/CN="+common_name])
  return
    
# generates certificates for attestation
def generate_certificates(snpguest: str):
    cert_dir = "./certs"

    if not os.path.exists(cert_dir):
        os.mkdir(cert_dir)

    try:
        subprocess.run(f"sudo {snpguest} certificates PEM {cert_dir}", shell=True, check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        raise Exception(f"Failed to generate certificates: {e}")

    return cert_dir

# generates attestation report
def generate_attestation_report(snpguest: str):
    report_file = "report.bin"

    try:
        subprocess.run(f"sudo {snpguest} report {report_file} request-file.txt --random", shell=True, check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        raise Exception(f"Failed to generate attestation report: {e}")

    return report_file

def run_server(snpguest: str, key_path: str, self_cert_path: str):
    port = 8080

    server = socket(AF_INET, SOCK_STREAM)
    server.bind(('', port))
    server.listen(10)

    context = SSLContext(PROTOCOL_TLS_SERVER)
    context.load_cert_chain(self_cert_path, key_path)
    sserver = context.wrap_socket(server, server_side=True)

    print(f"SERVER_HOST={gethostname()}")
    print(f"SERVER_PORT={sserver.getsockname()[1]}")

    s3 = boto3.client('s3')
    bucket_name = "gatk-amd-genomics-test-data"

    client_fs_base = os.path.expanduser("~/client")

    try:
        while True:
            connection, address = sserver.accept()
            if not os.path.exists(client_fs_base):
                os.mkdir(client_fs_base)

            try:
                # AMD SEV-SNP attestation
                # generate and send attestation
                report_file = generate_attestation_report(snpguest)

                with open(report_file, "rb") as f:
                    report_content = f.read()

                # Send the length of the attestation report to the client
                sendMessage(connection, report_content)

                # generate and send certificates
                cert_dir = generate_certificates(snpguest)

                for cert_file in os.listdir(cert_dir):
                    with open(os.path.join(cert_dir, cert_file), "rb") as f:
                        cert_content = f.read()

                    connection.send(cert_file.encode())
                    sendMessage(connection, cert_file)
                    sendMessage(connection, cert_content)
                
                connection.send("\r\n".encode())

                # change into client directory
                os.chdir(client_fs_base);

                while True:
                    # listen for client requests until there are no more
                    cmd = receiveMessage(connection).decode().split()
                    file_path = ''

                    if len(cmd) < 2 or cmd[0] not in ["DATA", "SCRIPT"]:
                        break
                    
                    if cmd[0] in ["DATA", "SCRIPT"]:
                        file_path = os.path.join(client_fs_base, cmd[1])
                        file_contents = receiveMessage(connection)

                        with open(file_path, "wb") as f:
                            f.write(file_contents)

                    if cmd[0] == "DATA":
                        # fetch data files specified in file_path from s3
                        with open(file_path, "r") as f:
                            data_files = f.readlines()

                        for data_file in data_files:
                            response = s3.get_object(Bucket=bucket_name, Key=data_file)
                            with open(data_file, "wb") as f:
                                f.write(response['Body'].read())

                            # decrypt file
                            subprocess.run(f"gpg --batch --output {data_file[:-4]} --passphrase gatk2025 --decrypt {data_file}", shell=True, check=True)
                        
                        print(f"Finished reading and decrypting data files in {file_path}")

                    elif cmd[0] == "SCRIPT":
                        result_path = cmd[2]
                        # set file_path as executable and execute script (with no arguments)
                        subprocess.run(f"chmod +x {file_path}; bash {file_path}", shell=True, check=True, capture_output=True)

                        # send result back to client
                        with open(os.path.join(client_fs_base, result_path), "rb") as f:
                            result_content = f.read()

                        sendMessage(connection, result_content)
                        print(f"Finished running script {file_path}")

            except Exception as e:
                print(e)

            # remove all files created for client before closing connection
            if os.getcwd() == client_fs_base:
                os.chdir("../")
            shutil.rmtree(pathlib.Path(client_fs_base))
            connection.close()
    except Exception as e:
        print(e)

    server.close()

def main():
    try:
        parser = argparse.ArgumentParser()

        parser.add_argument('-sg', '--snpguest', default=None, help="Location of the snpguest utility executable (default: fetches and builds snpguest from source)")
        parser.add_argument('-s', '--secrets_dir', default="~/secrets", help="Common name for generating self-signed certificate (default: ~/secrets)")
        parser.add_argument('-kf', '--key_file', default="server.key", help="Private key file (default: server.key)")
        parser.add_argument('-cf', '--cert_file', default="server.pem", help="Self-signed certificate file (default: server.pem)")
        parser.add_argument('-cn', '--common_name', default="localhost", help="Common name for generating self-signed certificate (default: localhost)")

        args = parser.parse_args()

        # generate private key and certificates for ssl
        secrets_dir = os.path.expand(args.secret_dir)
        if not os.path.exists(secrets_dir):
            os.mkdir(secrets_dir)

        key_path = os.path.join(secrets_dir, args.key_file)
        cert_path = os.path.expanduser(secrets_dir, args.cert_file)
        generate_private_key(key_path)
        generate_self_signed_cert(key_path, cert_path, args.common_name)
        
        if not args.snpguest:
            try:
                # fetch and build snpguest from source
                if not os.path.isdir("./snpguest"):
                    subprocess.run('git clone https://github.com/virtee/snpguest.git', shell=True, capture_output=True, check=True)
                if not os.path.isfile("./snpguest/target/release/snpguest"):
                    subprocess.run('cargo build -r', shell=True, capture_output=True, check=True, cwd="./snpguest/")

                args.snpguest = "./snpguest/target/release/snpguest"
            except subprocess.CalledProcessError as e:
                print(f"Failed to fetch and build snpguest from source: {e}")
                sys.exit(1)
        elif not os.path.isfile(args.snpguest()):
            print(f"Cannot find file {args.snpguest()}.")
        
        run_server(args.snpguest, key_path, cert_path)
    except Exception as e:
        print(f"Unexpected error occurred: {e}")
        sys.exit(1)



if __name__ == "__main__":
    main()

