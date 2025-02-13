import argparse
import os
import subprocess
import sys

from socket import *

def generate_certificates(snpguest: str):
    cert_dir = "./certs"

    if not os.path.exists(cert_dir):
        os.mkdir(cert_dir)

    try:
        subprocess.run(f"{snpguest} certificates PEM {cert_dir}", shell=True, check=True, capture_output=True)
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
                connection.send(len(report_content).to_bytes(4, byteorder='big'))
                # Send the attestation report to the client
                connection.sendall(report_content)

                # generate and send certificates
                cert_dir = generate_certificates(snpguest)

                for cert_file in os.listdir(cert_dir):
                    with open(os.path.join(cert_file), "rb") as f:
                        cert_content = f.read()

                    connection.send(cert_file.encode())
                    connection.send(len(cert_content).to_bytes(4, byteorder='big'))
                    connection.sendall(cert_content)
                
                connection.send("\r\n".encode())

                while True:
                    # listen for client requests until there are no more
                    client_msg = connection.recv(1024)

                    if not client_msg:
                        break

            except Exception as e:
                print(e)

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

