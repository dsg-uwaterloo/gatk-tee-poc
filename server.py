import argparse
import datetime
import random
import os
import subprocess
import sys
import shutil
import pathlib
import pytz
import time

import boto3
import botocore

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from helper import *
from ssl import *
from socket import *

# constants
S3 = boto3.client('s3', region_name='us-east-2')
DATA_BUCKET = "gatk-amd-genomics-test-data"
RESULT_BUCKET = "gatk-amd-genomics-result"
CLIENT_FS_BASE = os.path.expanduser("~/client")

RSA_PRIVATE_FILE = "rsa_priv.pem"
RSA_PUBLIC_FILE = "rsa_pub.pem"

# send self-signed certificate
def send_self_cert(socket, self_cert_path):
    with open(self_cert_path, "rb") as f:
        send_message(socket, f.read())

# generate rsa filename
def get_rsa_filename(infix: str):
    return "rsa_" + infix + ".pem"

# fetch and decrypt s3_sym_key_file
def decrypt_symmetric_key(s3_sym_key_file, secrets_dir):
    try:
        encrypted_path = os.path.join(secrets_dir, "encrypted.txt")
        decrypted_path = os.path.join(secrets_dir, "decrypted.txt")
        public_path = os.path.join(secrets_dir, RSA_PUBLIC_FILE)
        private_path = os.path.join(secrets_dir, RSA_PRIVATE_FILE)
        response = S3.get_object(Bucket=DATA_BUCKET, 
                                 Key=s3_sym_key_file, 
                                 IfModifiedSince=datetime.datetime.fromtimestamp(os.path.getmtime(public_path), tz=pytz.timezone('US/Eastern'))
                                 )
        
        with open(encrypted_path, "wb") as f:
            f.write(response['Body'].read())

        subprocess.run(["openssl", "pkeyutl", "-decrypt", "-inkey", private_path, "-in", encrypted_path, "-out", decrypted_path])

        with open(decrypted_path, "r") as f:
            decrypted = f.read()
        return decrypted
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidObjectState':
            raise Exception("Symmetric key encrypted with previous version of RSA public key")
        else:
            raise Exception("Unexpected exception while fetching symmetric key")

# generate rsa keypair for decrypting symmetric keys
def generate_rsa_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )
    return private_key

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

# sends attestation and handles requests for each TCP connection
def handle_client_connection(client_ssock, snpguest, secrets_dir):
    create_dirs([CLIENT_FS_BASE])

    try:
        # AMD SEV-SNP attestation
        # generate and send attestation
        report_file = generate_attestation_report(snpguest)

        with open(report_file, "rb") as f:
            report_content = f.read()

        # Send the length of the attestation report to the client
        send_message(client_ssock, report_content)

        # generate and send certificates
        cert_dir = generate_certificates(snpguest)

        for cert_file in os.listdir(cert_dir):
            with open(os.path.join(cert_dir, cert_file), "rb") as f:
                cert_content = f.read()

            send_message(client_ssock, cert_file.encode())
            send_message(client_ssock, cert_content)
        
        send_message(client_ssock, "\r\n".encode())

        # change into client directory
        os.chdir(CLIENT_FS_BASE);

        while True:
            # listen for client requests until there are no more
            cmd = receive_message(client_ssock).decode().split()
            file_path = ''

            if len(cmd) < 2 or cmd[0] not in ["DATA", "SCRIPT"]:
                break
            
            if cmd[0] in ["DATA", "SCRIPT"]:
                file_path = os.path.join(CLIENT_FS_BASE, cmd[1])
                file_contents = receive_message(client_ssock)

                with open(file_path, "wb") as f:
                    f.write(file_contents)

            if cmd[0] == "RSA":
                # share rsa public key
                with open(os.path.join(secrets_dir, RSA_PUBLIC_FILE), 'rb') as f:
                    send_message(client_ssock, f.read())
            elif cmd[0] == "DATA":
                # fetch and decrypt data files from s3
                start_time = time.time()
                # fetch data files specified in file_path from s3
                with open(file_path, "r") as f:
                    data_files = f.readlines()

                for data_file in data_files:
                    response = S3.get_object(Bucket=DATA_BUCKET, Key=data_file)
                    with open(data_file, "wb") as f:
                        f.write(response['Body'].read())

                    symmetric_key = decrypt_symmetric_key(response['Metadata']['symmetric-key'], secrets_dir)
                    # decrypt file
                    print(f"gpg --batch --output {data_file[:-4]} --passphrase {symmetric_key} --decrypt {data_file}")
                    subprocess.run(f"gpg --batch --output {data_file[:-4]} --passphrase {symmetric_key} --decrypt {data_file}", shell=True, check=True)
                
                print(f"Finished reading and decrypting data files in {file_path}")
                print(f"Time to fetch and decrypt data: {time.time() - start_time} seconds")

            elif cmd[0] == "SCRIPT":
                result_dir = cmd[2]
                create_dirs([result_dir])

                start_time = time.time()

                # set file_path as executable and execute script (with no arguments)
                subprocess.run(f"chmod +x {file_path}; bash {file_path}", shell=True, check=True, capture_output=True)
                print(f"Finished running script {file_path}")
                print(f"Time to run client script: {time.time() - start_time} seconds")

                start_time = time.time()
                # create new s3 directory
                s3_dir = "result-" + str(random.randint(0, sys.maxsize * 2 + 1))
                while "Common prefixes" in S3.list_objects(Bucket=RESULT_BUCKET, Prefix=s3_dir, Delimiter='/',MaxKeys=1):
                    s3_dir = "result-" + random.randint()

                # upload all files under result_dir to s3_dir
                for filename in os.listdir(result_dir):
                    file_path = os.path.join(result_dir, filename)
                    if os.path.isfile(file_path):
                        with open(file_path, "rb") as f:
                            S3.put_object(Body=f.read(), Bucket=RESULT_BUCKET, Key=os.path.join(s3_dir, filename))

                print(f"Time to upload results to S3: {time.time() - start_time} seconds")
                send_message(client_ssock, s3_dir.encode())
                print(f"Uploaded results to {s3_dir}")
                

    except Exception as e:
        print(e)

    # remove all files created for client before closing connection
    if os.getcwd() == CLIENT_FS_BASE:
        os.chdir("../")
    shutil.rmtree(pathlib.Path(CLIENT_FS_BASE))

# run server
def run_server(snpguest: str, key_path: str, self_cert_path: str, secrets_dir: str):
    port = 8080

    server_sock = socket(AF_INET, SOCK_STREAM)
    server_sock.bind(('', port))
    server_sock.listen(10)

    print(f"SERVER_HOST={gethostname()}")
    print(f"SERVER_PORT={server_sock.getsockname()[1]}")

    context = SSLContext(PROTOCOL_TLS_SERVER)
    context.load_cert_chain(self_cert_path, key_path)

    try:
        while True:
            connection, _ = server_sock.accept()
            # send self-signed certificate
            send_self_cert(connection, self_cert_path)
            client_ssock = context.wrap_socket(connection, server_side=True)

            handle_client_connection(client_ssock, snpguest, secrets_dir)

            client_ssock.close()
    except Exception as e:
        print(e)

    server_sock.close()

def main():
    try:
        parser = argparse.ArgumentParser()

        parser.add_argument('-sg', '--snpguest', default=None, help="Location of the snpguest utility executable (default: fetches and builds snpguest from source)")
        parser.add_argument('-s', '--secrets_dir', default="~/secrets", help="Common name for generating self-signed certificate (default: ~/secrets)")
        parser.add_argument('-kf', '--key_file', default="server.key", help="Private key file (default: server.key)")
        parser.add_argument('-cf', '--cert_file', default="server.pem", help="Self-signed certificate file (default: server.pem)")
        parser.add_argument('-cn', '--common_name', default=gethostname(), help=f"Common name for generating self-signed certificate (default: {gethostname()})")

        args = parser.parse_args()

        # generate private key and certificates for ssl
        secrets_dir = os.path.expanduser(args.secrets_dir)
        if not os.path.exists(secrets_dir):
            os.mkdir(secrets_dir)

        key_path = os.path.join(secrets_dir, args.key_file)
        cert_path = os.path.join(secrets_dir, args.cert_file)
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

        # generate and save rsa keypair if either key does not already exist
        private_path = os.path.join(secrets_dir, RSA_PRIVATE_FILE)
        public_path = os.path.join(secrets_dir, RSA_PUBLIC_FILE)
        if not os.path.isfile(private_path) or not os.path.isfile(public_path):
            private_key = generate_rsa_key()

            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            public_pem = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            with open(private_path, 'wb') as f:
                f.write(private_pem)
            with open(public_path, 'wb') as f:
                f.write(public_pem)
        
        run_server(args.snpguest, key_path, cert_path, secrets_dir)
    except Exception as e:
        print(f"Unexpected error occurred: {e}")
        sys.exit(1)



if __name__ == "__main__":
    main()

