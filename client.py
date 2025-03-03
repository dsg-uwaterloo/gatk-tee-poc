import argparse
import os
import subprocess
import sys
import shutil
import pathlib

from socket import *
from ssl import *

def create_dirs(dirs):
    for dir in dirs:
        if not os.path.exists(dir):
            os.mkdir(dir)

def remove_dirs(dirs):
    for dir in dirs:
        if os.path.exists(dir):
            shutil.rmtree(pathlib.Path(dir))

def receive_message(socket):
    message_size = int.from_bytes(socket.recv(4), byteorder='big')
    return socket.recv(message_size)

def send_message(socket, message):
    socket.send(len(message).to_bytes(4, byteorder='big'))
    socket.sendall(message)

def fetch_server_certificate(socket, server_cert_file):
    server_cert_content = receive_message(socket)

    with open(server_cert_file, 'wb') as f:
        f.write(server_cert_content)
    return

def fetch_snp_certificates(snpguest, cert_dir, proc_model, att_report_path):
    """
    Regular attestation workflow
    """

    cmd_ca = f"{snpguest} fetch ca pem {proc_model} {cert_dir}"
    cmd_vcek = f"{snpguest} fetch vcek pem {proc_model} {cert_dir} {att_report_path}"

    try:
        subprocess.run(cmd_ca, shell=True, check=True)
        subprocess.run(cmd_vcek, shell=True, check=True)

        # Check if the required files exist in the cert_dir
        required_files = ['ark.pem', 'ask.pem', 'vcek.pem']

        for file in required_files:
            file_path = os.path.join(cert_dir, file)
            if os.path.exists(file_path):
                required_files.remove(file)

        if required_files:
            raise Exception(f"Error: Failed to retrieve certificates. Missing files: {', '.join(required_files)}")

        print("Certificates acquired successfully.\n")
    except subprocess.CalledProcessError as e:
        raise Exception(f"Failed to fetch certificates: {e}")

def verify_snp_certificates(snpguest, cert_dir):
    """
    Regular attestation workflow
    """

    expected_output = [
        "The AMD ARK was self-signed!",
        "The AMD ASK was signed by the AMD ARK!",
        "The VCEK was signed by the AMD ASK!"
    ]

    try:
        output = subprocess.check_output(f"{snpguest} verify certs {cert_dir}", shell=True, universal_newlines=True)

        if expected_output != output:
            raise Exception(f"Certificate validation failed: \n{output}")

        print(f"Certificate validation succeeded: \n{output}")
    except subprocess.CalledProcessError as e:
        raise Exception(f"Failed to fetch certificates: {e}")
    
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


def run_client(server_host, server_port, root_cert_path, snpguest, report_dir, cert_dir, data_path, gatk_script, result_path, key_path, self_cert_path):
    client_sock = socket(AF_INET, SOCK_STREAM)

    #client.settimeout(10)
    client_sock.connect((server_host, server_port))
    #client.settimeout(None)

    fetch_server_certificate(client_sock, root_cert_path)
    context = SSLContext(PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(self_cert_path)
    client_ssock = context.wrap_socket(client_sock, server_hostname=server_host)

    try:
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

        #fetch_certificates(snpguest, cert_dir, proc_model, report_path)
        verify_vlek(cert_dir)
        verify_attestation(snpguest, report_path, cert_dir)

        # send file with required data files that server should fetch from s3 bucket
        with open(data_path, "rb") as f:
            data_content = f.read()

        send_message(client_ssock, f"DATA {os.path.basename(data_path)}".encode())
        send_message(client_ssock, data_content)

        # send GATK command script
        with open(gatk_script, "rb") as f:
            script_content = f.read()

        send_message(client_ssock, f"SCRIPT {os.path.basename(gatk_script)} {result_path}".encode())
        send_message(client_ssock, script_content)

        # get results and write to result_path
        result_content = receive_message(client_ssock)

        with open(result_path, "wb") as f:
            f.write(result_content)

        print(f"Results received and stored in {result_path}")

    except Exception as e:
        print(e)
        client_sock.close()
        sys.exit(1)
    
    client_sock.close()


def main():
    try:
        parser = argparse.ArgumentParser()

        parser.add_argument('-sh', '--server_host', required=True, help="Machine that the server is running on")
        parser.add_argument('-sp', '--server_port', default=8080, help="Server port number (default: 8080)")
        parser.add_argument('-rf', '--root_cert_file', default="server.pem", help="Trusted root certificate base (default: server.pem)")
        parser.add_argument('-sg', '--snpguest', default=None, help="Location of the snpguest utility executable (default: fetches and builds snpguest from source)")
        parser.add_argument('-rd', '--report_dir', default=".", help="Attestation report directory (default: .)")
        parser.add_argument('-cd', '--cert_dir', default="./certs", help="Location to write certificates to (default: ./certs)")
        #parser.add_argument('-pm', '--processor_model', default="milan", help="Processor model (default: milan)")
        parser.add_argument('-d', '--data', required=True, help="Name of file containing all newline separated data files required to execute gatk script")
        parser.add_argument('-gs', '--gatk_script', required=True, help="Script to fetch gatk executable and run gatk commands")
        parser.add_argument('-r', '--result', required=True, help="Name of file that results of executing gatk_script will be stored in relative to location of gatk_script")

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
        elif not os.path.isfile(args.snpguest):
            print(f"Cannot find executable {args.snpguest}.")

        create_dirs([args.report_dir, args.cert_dir])
        run_client(args.server_host, int(args.server_port), os.path.join(args.cert_dir, args.root_cert_file), args.snpguest, args.report_dir, args.cert_dir, args.data, args.gatk_script, args.result, key_path, cert_path)
        remove_dirs([args.report_dir, args.cert_dir])
    except Exception as e:
        print(f"Unexpected error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()