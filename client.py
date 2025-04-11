import argparse
import os
import subprocess
import sys
import time

from helper import *
from socket import *
from ssl import *

# global variables
SECURE = True

def fetch_server_certificate(socket, server_cert_file):
    server_cert_content = receive_message(socket)

    with open(server_cert_file, 'wb') as f:
        f.write(server_cert_content)
    return

def verify_vlek(cert_dir):
    """
    Extended attestation workflow
    """

    expected_output = "certs/vlek.pem: OK"
    try:
        subprocess.run(f"sudo curl --proto '=https' --tlsv1.2 -sSf https://kdsintf.amd.com/vlek/v1/Milan/cert_chain -o {os.path.join(cert_dir, "cert_chain.pem")}", shell=True, check=True)
        output = subprocess.check_output(f"sudo openssl verify --CAfile {os.path.join(cert_dir, "cert_chain.pem")} {os.path.join(cert_dir, "vlek.pem")}", shell=True, universal_newlines=True)

        if expected_output not in output:
            raise Exception(f"vlek validation failed: \n{output}")
        
        print(f"vlek validation succeeded: \n{output}")
    except subprocess.CalledProcessError as e:
        raise Exception(f"Failed to verify vlek.pem: {e}")

def verify_attestation(snpguest, report_path, cert_dir):
    expected_output = [
        "Reported TCB Boot Loader from certificate matches the attestation report.",
        "Reported TCB TEE from certificate matches the attestation report.",
        "Reported TCB SNP from certificate matches the attestation report.",
        "Reported TCB Microcode from certificate matches the attestation report.",
        "VEK signed the Attestation Report!"
    ]
    cmd = f"{snpguest} verify attestation {cert_dir} {report_path}"
    
    try:
        output = subprocess.check_output(cmd, shell=True, universal_newlines=True)

        split_output = output.strip().splitlines()
        if not all(line in split_output for line in expected_output):
            raise Exception(f"Attestation validation failed: \n{output}")            
        
        print(f"Attestation validation succeeded: \n{output}")
    except subprocess.CalledProcessError as e:
        raise Exception(f"Failed to verify attestation report: {e}")


def run_client(server_host, server_port, root_cert_path, snpguest, report_dir, cert_dir, data_path, gatk_script, result_dir):
    client_sock = socket(AF_INET, SOCK_STREAM)

    client_sock.connect((server_host, server_port))

    fetch_server_certificate(client_sock, root_cert_path)
    context = SSLContext(PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(root_cert_path)
    client_ssock = context.wrap_socket(client_sock, server_hostname=server_host)

    try:
        if SECURE:
            start_time = time.time()
            # receive and write attestation report to file
            report_path = os.path.join(report_dir, "report.bin")
            report_contents = receive_message(client_ssock)

            with open(report_path, "wb") as f:
                f.write(report_contents)

            # get certificates
            cert_filename = receive_message(client_ssock).decode()

            while cert_filename != "\r\n":
                cert_contents = receive_message(client_ssock)

                with open(os.path.join(cert_dir, cert_filename), "wb") as f:
                    f.write(cert_contents)

                cert_filename = receive_message(client_ssock).decode()

            verify_vlek(cert_dir)
            verify_attestation(snpguest, report_path, cert_dir)

            print(f"Total attestation time: {time.time() - start_time} seconds")

        start_time = time.time()

        # send file with required data files that server should fetch from s3 bucket
        with open(data_path, "rb") as f:
            data_content = f.read()

        send_message(client_ssock, f"DATA {os.path.basename(data_path)}".encode())
        send_message(client_ssock, data_content)

        # send GATK command script
        with open(gatk_script, "rb") as f:
            script_content = f.read()

        send_message(client_ssock, f"SCRIPT {os.path.basename(gatk_script)} {result_dir}".encode())
        send_message(client_ssock, script_content)

        # get results and write to result_path
        s3_result_dir = receive_message(client_ssock).decode()

        print(f"Results received and stored in s3 under {s3_result_dir}")
        print(f"Total data fetching and script execution time: {time.time() - start_time} seconds")

    except Exception as e:
        client_ssock.close()
        raise Exception(e)
    
    client_ssock.close()


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument('-sh', '--server_host', required=True, help="Machine that the server is running on")
    parser.add_argument('-sp', '--server_port', default=8080, help="Server port number (default: 8080)")
    parser.add_argument('-rf', '--root_cert_file', default="server.pem", help="Trusted root certificate base (default: server.pem)")
    parser.add_argument('-sg', '--snpguest', default=None, help="Location of the snpguest utility executable (default: fetches and builds snpguest from source)")
    parser.add_argument('-rd', '--report_dir', default=".", help="Attestation report directory (default: .)")
    parser.add_argument('-cd', '--cert_dir', default="./certs", help="Location to write certificates to (default: ./certs)")
    parser.add_argument('-d', '--data', required=True, help="Name of file containing all newline separated data files required to execute gatk script")
    parser.add_argument('-gs', '--gatk_script', required=True, help="Script to fetch gatk executable and run gatk commands")
    parser.add_argument('-r', '--result', required=True, help="Name of directory that results of executing gatk_script will be stored in relative to location of gatk_script")
    parser.add_argument('-is', '--insecure', action='store_true', help="Flag for server running script outside of a trusted execution environment")

    args = parser.parse_args()

    if args.insecure:
        global SECURE
        SECURE = False

    create_dirs([args.report_dir, args.cert_dir])

    try:
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
        elif not os.path.isfile(args.snpguest):
            print(f"Cannot find executable {args.snpguest}.")

        start_time = time.time()
        run_client(args.server_host, int(args.server_port), os.path.join(args.cert_dir, args.root_cert_file), args.snpguest, args.report_dir, args.cert_dir, args.data, args.gatk_script, args.result)
        print(f"Total end-to-end execution time: {time.time() - start_time} seconds")
    except Exception as e:
        print(f"Error: {e}")
        remove_dirs([args.report_dir, args.cert_dir])
        sys.exit(1)

    # clean-up
    remove_dirs([args.report_dir, args.cert_dir])

if __name__ == "__main__":
    main()