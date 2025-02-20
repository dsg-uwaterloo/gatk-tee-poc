import argparse
import os
import subprocess
import sys

import boto3

from socket import *

def sendFileContents(socket, file_content):
    socket.send(len(file_content).to_bytes(4, byteorder='big'))
    socket.sendall(file_content)
    

def generate_certificates(snpguest: str):
    cert_dir = "./certs"

    if not os.path.exists(cert_dir):
        os.mkdir(cert_dir)

    try:
        subprocess.run(f"sudo {snpguest} certificates PEM {cert_dir}", shell=True, check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        raise Exception(f"Failed to generate certificates: {e}")

    return cert_dir

def generate_attestation_report(snpguest: str):
    report_file = "report.bin"

    try:
        subprocess.run(f"sudo {snpguest} report {report_file} request-file.txt --random", shell=True, check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        raise Exception(f"Failed to generate attestation report: {e}")

    return report_file

def run_server(snpguest:str):
    port = 8080

    server = socket(AF_INET, SOCK_STREAM)
    server.bind(('', port))
    server.listen(10)

    print(f"SERVER_HOST={gethostname()}")
    print(f"SERVER_PORT={server.getsockname()[1]}")

    s3 = boto3.client('s3')
    bucket_name = "gatk-amd-genomics-test-data"

    try:
        while True:
            connection, address = server.accept()

            try:
                # AMD SEV-SNP attestation
                # generate and send attestation
                report_file = generate_attestation_report(snpguest)

                with open(report_file, "rb") as f:
                    report_content = f.read()

                # Send the length of the attestation report to the client
                sendFileContents(connection, report_content)

                # generate and send certificates
                cert_dir = generate_certificates(snpguest)

                for cert_file in os.listdir(cert_dir):
                    with open(os.path.join(cert_dir, cert_file), "rb") as f:
                        cert_content = f.read()

                    connection.send(cert_file.encode())
                    sendFileContents(connection, cert_content)
                
                connection.send("\r\n".encode())

                while True:
                    # listen for client requests until there are no more
                    cmd = connection.recv(1024).decode().split()
                    file_path = ''

                    if len(cmd) < 2 or cmd[0] not in ["DATA", "SCRIPT"]:
                        break
                    
                    if cmd[0] in ["DATA", "SCRIPT"]:
                        file_path = cmd[1]
                        file_size = int.from_bytes(connection.recv(4), byteorder='big')
                        file_contents = connection.recv(file_size)

                        with open(file_path, "wb") as f:
                            f.write(file_contents)

                    if cmd[0] == "DATA":
                        # fetch data files specified in file_path from s3
                        with open(file_path, "r") as f:
                            data_files = f.readlines()

                        for data_file in data_files:
                            response = s3.get_object(Bucket=bucket_name, Key=data_file)
                            with open(file_path, "wb") as f:
                                f.write(response['Body'].read())

                            # decrypt file
                            subprocess.run(f"gpg --batch --output {data_file} --passphrase gatk2025 --decrypt {data_file}.gpg", shell=True, check=True)

                    elif cmd[0] == "SCRIPT":
                        # set file_path as executable and execute script (with no arguments)
                        subprocess.run(f"chmod +x {file_path}; bash {file_path} > result.txt", shell=True, check=True, capture_output=True)

                        # send result back to client
                        with open("result.txt", "rb") as f:
                            result_content = f.read()

                        sendFileContents(connection, result_content)

            except Exception as e:
                print(e)

            # TODO: remove all files created for client before closing connection
            connection.close()
    except Exception as e:
        print(e)

    server.close()

def main():
    try:
        parser = argparse.ArgumentParser()

        parser.add_argument('-sg', '--snpguest', default=None, help="Location of the snpguest utility executable (default: fetches and builds snpguest from source)")

        args = parser.parse_args()
        
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
        
        run_server(args.snpguest)
    except Exception as e:
        print(f"Unexpected error occurred: {e}")
        sys.exit(1)



if __name__ == "__main__":
    main()

