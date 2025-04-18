import os

import json

import logging

import argparse

import hvac

import subprocess

import requests

import datetime

from concurrent.futures import ThreadPoolExecutor, as_completed

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from cryptography.hazmat.primitives import serialization, hashes

from cryptography.hazmat.primitives.asymmetric import rsa, padding


class IgnoreSpecificWarningFilter(logging.Filter):

    def filter(self, record):

        # Check if the message contains the common part you want to ignore

        # Right now we want to ignore the printing of the vault secret location

        if "Vault error occurred: None" in record.getMessage():

            return False  # Return False to filter out this log

        return True  # Allow other logs


# Set up logging with the INFO level

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


# Add the filter to the logger

logger = logging.getLogger()

logger.addFilter(IgnoreSpecificWarningFilter())


class RSACrypt:

    def __init__(self, path: None):

        self.path=path

  

    def generate_keys(self):

        private_key = rsa.generate_private_key(

            public_exponent=65537,

            key_size=2048

        )

        public_key = private_key.public_key()


        if self.path is not None:

        # Save private key

            with open(f"{self.path}/private_key.pem", "wb") as private_file:

                private_file.write(private_key.private_bytes(

                    encoding=serialization.Encoding.PEM,

                    format=serialization.PrivateFormat.PKCS8,

                    encryption_algorithm=serialization.NoEncryption()

                ))

      

            # Save public key

            with open(f"{self.path}/public_key.pem", "wb") as public_file:

                public_file.write(public_key.public_bytes(

                    encoding=serialization.Encoding.PEM,

                    format=serialization.PublicFormat.SubjectPublicKeyInfo

                ))

              

        else:

        # Save private key

            with open("private_key.pem", "wb") as private_file:

                private_file.write(private_key.private_bytes(

                    encoding=serialization.Encoding.PEM,

                    format=serialization.PrivateFormat.PKCS8,

                    encryption_algorithm=serialization.NoEncryption()

                ))

      

            # Save public key

            with open("public_key.pem", "wb") as public_file:

                public_file.write(public_key.public_bytes(

                    encoding=serialization.Encoding.PEM,

                    format=serialization.PublicFormat.SubjectPublicKeyInfo

                ))

  

        print("RSA key pair generated successfully!")


    # Load public key

    def load_public_key(self):

        if "-----BEGIN PUBLIC KEY-----" in self.path:

        # Assume it's a direct key string

            return serialization.load_pem_public_key(self.path.encode())

        else:

            # Assume it's a file path

            with open(self.path, "rb") as key_file:

                return serialization.load_pem_public_key(key_file.read())

  

    # Load private key

    def load_private_key(self):

        if "-----BEGIN PRIVATE KEY-----" in self.path:

        # Assume it's a direct key string

            return serialization.load_pem_private_key(self.path.encode(), password=None)

        else:

            # Assume it's a file path

            with open(self.path, "rb") as key_file:

                return serialization.load_pem_private_key(key_file.read(), password=None)

  

    # Encrypt a file using RSA public key

    def encrypt_file(self, file_path):

        public_key = self.load_public_key()


        # Generate a random AES key (256-bit)

        aes_key = os.urandom(32)

        iv = os.urandom(16)  # AES uses a 16-byte IV for CBC mode


        # Encrypt the file with AES

        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))

        encryptor = cipher.encryptor()


        with open(file_path, "rb") as file:

            plaintext = file.read()


        # Padding to ensure multiple of 16 bytes

        padding_length = 16 - (len(plaintext) % 16)

        padded_plaintext = plaintext + bytes([padding_length] * padding_length)


        encrypted_data = encryptor.update(padded_plaintext) + encryptor.finalize()


        # Encrypt the AES key with RSA

        encrypted_aes_key = public_key.encrypt(

            aes_key + iv,  # Encrypt both key and IV

            padding.OAEP(

                mgf=padding.MGF1(algorithm=hashes.SHA256()),

                algorithm=hashes.SHA256(),

                label=None

            )

        )


        # Save encrypted data

        with open(file_path, "wb") as encrypted_file:

            encrypted_file.write(encrypted_aes_key + encrypted_data)


        print(f"File '{file_path}' encrypted successfully as '{file_path}.enc'")


    def decrypt_file(self, encrypted_file_path, output_file_path: None):

        private_key = self.load_private_key()


        with open(encrypted_file_path, "rb") as encrypted_file:

            encrypted_content = encrypted_file.read()


        encrypted_aes_key = encrypted_content[:256]  # RSA 2048 encrypted key is 256 bytes

        encrypted_data = encrypted_content[256:]


        # Decrypt AES key and IV

        decrypted_key_iv = private_key.decrypt(

            encrypted_aes_key,

            padding.OAEP(

                mgf=padding.MGF1(algorithm=hashes.SHA256()),

                algorithm=hashes.SHA256(),

                label=None

            )

        )


        aes_key = decrypted_key_iv[:32]

        iv = decrypted_key_iv[32:]


        # Decrypt the file with AES

        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))

        decryptor = cipher.decryptor()


        decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()


        # Remove padding

        padding_length = decrypted_padded_data[-1]

        decrypted_data = decrypted_padded_data[:-padding_length]


        # with open(output_file_path, "wb") as decrypted_file:

        #     decrypted_file.write(decrypted_data)


        logging.info(f"File '{encrypted_file_path}' decrypted successfully'")

      

        return decrypted_data


class VaultClient:

    """Handles Vault authentication and client initialization."""


    def __init__(self, source: False, dest: False, vault_addr_source, vault_token_source, vault_addr_dest, vault_token_dest, namespace_source, namespace_dest):

        self.source = source

        self.dest = dest

      

        if source:

            self.vault_addr_source = vault_addr_source

            self.vault_token_source = vault_token_source

            self.namespace_source = namespace_source

            if self.vault_addr_source is None or self.vault_token_source is None:

                raise ValueError("Vault address or token is missing. Set VAULT_ADDR_SOURCE and VAULT_TOKEN_SOURCE.")

            if self.namespace_source is None:

                self.client_source = hvac.Client(url=self.vault_addr_source, token=self.vault_token_source)

            else:

              

                self.client_source = hvac.Client (url=self.vault_addr_source, token=self.vault_token_source, namespace=self.namespace_source)

            if not self.client_source.is_authenticated():

                raise ValueError("Vault authentication failed for SOURCE. Check your token.")

        if dest:

            self.vault_addr_dest = vault_addr_dest

            self.vault_token_dest = vault_token_dest

            self.namespace_dest = namespace_dest

            if self.vault_addr_dest is None or self.vault_token_dest is None:

                raise ValueError("Vault address or token is missing. Set VAULT_ADDR_DEST and VAULT_TOKEN_DEST.")

            if self.namespace_dest is None:

                self.client_dest = hvac.Client(url=self.vault_addr_dest, token=self.vault_token_dest)

            else:

                self.client_dest = hvac.Client(url=self.vault_addr_dest, token=self.vault_token_dest, namespace=self.namespace_dest)

            if not self.client_dest.is_authenticated():

                raise ValueError("Vault authentication failed for DEST. Check your token.")


 

class VaultSecretsManager:

    """Handles Vault secret operations such as listing secrets."""


    def __init__(self, vault_client: VaultClient):

        if vault_client.source:

            self.client_source = vault_client.client_source

        if vault_client.dest:

            self.client_dest = vault_client.client_dest


    def check_permissions(self, path, capabilities_self):

        """Check if the current token has the required capabilities for a given path."""

        try:

            response = self.client_source.sys.get_capabilities(paths=[path])

            return all(cap in response['capabilities'] for cap in capabilities_self)

        except hvac.exceptions.InvalidRequest as e:

            logging.error(f"Error checking capabilities: {e}")

            return False

      

    def list_secrets(self, mount, path):

        """List secrets at the given mount and path."""

        try:

            response = self.client_source.secrets.kv.v2.list_secrets(mount_point=mount, path=path)

            return response['data'].get('keys', [])

        except hvac.exceptions.Forbidden:

            logging.warning(f"Permission denied for listing secrets at {path}.")

        except hvac.exceptions.VaultError as e:

            logging.warning(f"Vault error occurred: {e}")

        except Exception as e:

            logging.warning(f"Unexpected error: {e}")

          

    def get_vault_secret(self, mount, secret_path):

        """Read the secret and its metadata."""

        try:

            response = self.client_source.secrets.kv.v2.read_secret(mount_point=mount, path=secret_path)

            secret = response["data"]

            return secret

        except hvac.exceptions.Forbidden:

            logging.warning(f"Permission denied for reading secret at {secret_path}.")

        except hvac.exceptions.VaultError as e:

            logging.warning(f"Vault error occurred while retrieving the secret: {e}")

        except Exception as e:

            logging.warning(f"Unexpected error while retrieving the secret: {e}")

        

    # !!! This is made for only one secrets_engine !!!

    # !!! Uncomment this if you want to use for multiple secrets-engines !!!

    # def list_secrets_engines(self, destination: False, source: False):

    #     if destination == True:

    #         return self.client_dest.sys.list_mounted_secrets_engines()['data']

    #     elif source == True:

    #         return self.client_source.sys.list_mounted_secrets_engines()['data']

          

    def import_secret(self, path, secret, mount_point, custom_metadata):

        # mounts_list = self.list_secrets_engines(True, False)

        # mounts = [s.replace("/", "") for s in mounts_list.keys()]

        # if mount_point not in mounts:

        #     logging.info(f"{mount_point} in {mounts}")

          

        #     self.client_dest.sys.enable_secrets_engine(

        #             backend_type='kv',

        #             path=mount_point,

        #             options={"version": 2}

        #         )

      

        self.client_dest.secrets.kv.v2.create_or_update_secret(

                mount_point = mount_point,

                path = path,

                secret = secret

            )

        self.client_dest.secrets.kv.v2.update_metadata(

                mount_point = mount_point,

                path = path,

                custom_metadata = custom_metadata

            )


    def recursive_search(self, mount, path, l):

        try:

            paths = self.list_secrets(mount, path)

            for p in paths:

                self.recursive_search(mount, path + p, l)

        except Exception:

            l.append(path)

          

    def export_secrets(self, mount_point, path: None, export_path: None, output_file: None, encrypt: None):

        if mount_point not in ["cubbyhole", "secret", "identity", "sys"]: #basically not the default secrets engines created by vault

            secretsPathsInVault = list()

            if path is not None:

                self.recursive_search(mount_point, path, secretsPathsInVault)

            else:

                self.recursive_search(mount_point, "", secretsPathsInVault)

            secretsOutput = dict()

            for p in secretsPathsInVault:

                secretsOutput[p] = self.get_vault_secret(mount_point, p)

            if export_path is None:

                with open(output_file, "w") as json_file:

                    json.dump(secretsOutput, json_file, indent=4)

                if encrypt is not None:

                    rsaEncrypter = RSACrypt(encrypt)

                    rsaEncrypter.encrypt_file(output_file)

                    logging.info(f"Encrypted backup saved at {output_file}")

                else:

                    logging.info(f"Backup saved at {output_file}")

            else:

                with open(f"{export_path}/{output_file}", "w") as json_file:

                    json.dump(secretsOutput, json_file, indent=4)

                if encrypt is not None:

                    rsaEncrypter = RSACrypt(encrypt)

                    rsaEncrypter.encrypt_file(f"{export_path}/{output_file}")

                    logging.info(f"Encrypted backup saved at {export_path}/{output_file}")

                else:

                    logging.info(f"Backup saved at {export_path}/{output_file}")

        else:

            logging.info("The default secrets engines are excluded!")

  

    def import_secrets(self, import_path, decryption: None):

        if decryption is not None:

            rsaDecrypter = RSACrypt(decryption)

            secretsMap = json.loads(rsaDecrypter.decrypt_file(import_path, None))

            for key in secretsMap:

                self.import_secret(key, secretsMap[key]["data"], "your_secrets_engine", secretsMap[key]["metadata"]["custom_metadata"])


        else:

            with open(f"{import_path}", "r") as backup_file:

                secretsMap = json.load(backup_file)

            # for key in secretsMap:
                
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = [
                    executor.submit(
                        self.import_secret,
                        key,
                        secretsMap[key]["data"],
                        "your_secrets_engine",
                        secretsMap[key]["metadata"]["custom_metadata"]
                    )
                    for key in secretsMap
                ]

                for future in as_completed(futures):
                    try:
                        future.result()  # will raise exception if one occurred
                    except Exception as e:
                        print(f"Error importing secret: {e}")

                # self.import_secret(key, secretsMap[key]["data"], "your_secrets_engine", secretsMap[key]["metadata"]["custom_metadata"])

              

    def sync(self):

        paths = ["your_directory_1", "your_directory_2"]

        date = datetime.datetime.now().strftime("%Y%m%d_%H%M")

        for path in paths:

            output_file = f"{date}_your_secrets_engine_{path}.json"

            self.export_secrets("your_secrets_engine", f"{path}/", None, output_file, None)

            self.import_secrets(f"{output_file}", None)

            os.remove(f"{output_file}")

            logging.info(f"Sync completed succesffully for directory {path}!")

        logging.info("Sync completed succesffully for all directories inside your_secrets_engine mount point")

        # else:

        #     engines = self.list_secrets_engines(False, True)

        #     logging.info(f"{json.dumps(engines)}")

        #     for engine in engines:

        #         eng = engine.split("/")

        #         if eng[0] not in ["cubbyhole", "secret", "identity", "sys"]:

        #             self.export_secrets(eng[0], None, None)

        #             current_time = datetime.now()

        #             to_save_time = current_time.strftime('%Y%m%d')

        #             self.import_secrets(f"{eng[0]}_{to_save_time}.json", None)

        #             os.remove(f"{eng[0]}_{to_save_time}.json")

        #             logging.info(f"Sync completed succesffully for secrets engine {eng[0]}!")

        #     logging.info("SYNC COMPLETED SUCCESFFULLY FOR ENTIRE VAULT!")

          

    def get_openstack_token(self, auth_url, storage_user, storage_password, project):

        token_body = {

            "auth": {

                "identity": {

                    "methods": ["password"],

                    "password": {

                        "user": {

                            "domain": {"name": "ccadmin"},

                            "name": storage_user,

                            "password": storage_password

                        }

                    }

                },

                "scope": {

                    "project": {

                        "domain": {"name": "ccadmin"},

                        "name": project

                    }

                }

            }

        }

        headers = {"Content-Type": "application/json"}

        response = requests.post(f"{auth_url}/v3/auth/tokens?nocatalog", headers=headers, json=token_body)

      

        if response.status_code == 201:

            return response.headers.get("X-Subject-Token")

        return None

          

    def upload_file(self, os_token, os_object_storage_url, container_account, container, file_path):

        headers = {

            "X-Auth-Token": os_token,

            "X-Object-Meta-User": os.environ.get("STORAGE_USER"),

            "X-Object-Meta-Type": "Original"

        }

        with open(file_path, "rb") as f:

            response = requests.put(f"{os_object_storage_url}/v1/{container_account}/{container}/{os.path.basename(file_path)}", headers=headers, data=f)

        return response.status_code == 201

          

   

       

           

           

 

def main():

  

   

    parser = argparse.ArgumentParser(prog="Vault Sync/Backup script", allow_abbrev=False)

  

    subparsers = parser.add_subparsers(dest='command')

  

    sync_parser = subparsers.add_parser('sync')

    read_address_group = sync_parser.add_mutually_exclusive_group(required=True)

    read_token_group = sync_parser.add_mutually_exclusive_group(required=True)

    write_address_group = sync_parser.add_mutually_exclusive_group(required=True)

    write_token_group = sync_parser.add_mutually_exclusive_group(required=True)

    read_address_group.add_argument('--source-address', nargs=1, help='Vault Source Address (Read address).')

    write_address_group.add_argument('--destination-address', nargs=1, help='Vault Destination Address (Write address).')

    read_token_group.add_argument('--source-token', nargs=1, help='Vault Source Token (Read token).')

    write_token_group.add_argument('--destination-token', nargs=1, help='Vault Destination Token (Write token).')

 

  

    backup_export_parser = subparsers.add_parser('backup-export')

  

    # backup_restore_parser = subparsers.add_parser('backup-restore')

    # write_address_group = backup_restore_parser.add_mutually_exclusive_group(required=True)

    # write_token_group = backup_restore_parser.add_mutually_exclusive_group(required=True)

    # path_file_group = backup_restore_parser.add_mutually_exclusive_group(required=True)

    # decryption_key_group = backup_restore_parser.add_mutually_exclusive_group(required=False)

    # write_address_group.add_argument('--destination-address', nargs=1, help='Vault Destination Address (Write address).')

    # write_token_group.add_argument('--destination-token', nargs=1, help='Vault Destination Token (Write token).')

    # path_file_group.add_argument('--path', nargs=1, help='Path of the file to import')

    # decryption_key_group.add_argument('--decryption-private-key', nargs=1, help='[OPTIONAL] Provide the private decryption key')

  

    generate_rsa_keys_parser = subparsers.add_parser('generate-rsa-keys')

    path_for_keys_group = generate_rsa_keys_parser.add_mutually_exclusive_group(required=False)

    path_for_keys_group.add_argument('--path', nargs=1, help='Path where to store the rsa key pairs')

  

   

    args = parser.parse_args()

  

    if args.command == "generate-rsa-keys":

        if args.path is not None:

            rsaGenerator = RSACrypt(args.path[0])

            rsaGenerator.generate_keys()

        else:

            rsaGenerator = RSACrypt(None)

            rsaGenerator.generate_keys()

    elif args.command == "backup-export":

        #parameters from values.yaml in vault backup

        VAULT_ADDR = os.environ.get("VAULT_ADDR")

        VAULT_NAMESPACE = os.environ.get("VAULT_NAMESPACE")

        VAULT_TOKEN = os.environ.get("VAULT_TOKEN")

        VAULT_ROLE = os.environ.get("VAULT_ROLE")

        KUBERNETES_AUTH_PATH = os.environ.get("KUBERNETES_AUTH_PATH")

        VAULT_SKIP_VERIFY = os.environ.get("VAULT_SKIP_VERIFY")

        ENCRYPT_BACKUP = os.environ.get("ENCRYPT_BACKUP")

        HVAC_BACKUP_PUBLIC_KEY = os.environ.get("HVAC_BACKUP_PUBLIC_KEY")

        secret_paths = os.environ.get("VAULT_SECRET_PATHS").split()

        region = os.environ.get("REGION")

        date = datetime.datetime.now().strftime("%Y%m%d_%H%M")

        container = "vault-backup"

        os_auth_url = f"https://your_auth_url.{region}"

        os_object_storage_url = f"https://your_object_storage_url.{region}"

        vaultClient = VaultClient(True, False, VAULT_ADDR, VAULT_TOKEN, None, None, VAULT_NAMESPACE, None)
        
        vaultManager = VaultSecretsManager(vaultClient)

      

        logging.info("Vault Secret export started")

        logging.info("Fetching Openstack Token")

        os_token = vaultManager.get_openstack_token(os_auth_url, os.environ.get("STORAGE_USER"), os.environ.get("STORAGE_PASSWORD"), os.environ.get("PROJECT"))

      

        if not os_token:

            logging.error("Fetching Openstack Token failed. Check required credentials.")

            exit(1)

      

        logging.info("Acquired OS token.")

      

        for kv in secret_paths:

            logging.info(f"Starting to back up secret path '{kv}'")

            output_file = f"/tmp/{date}_{kv.replace('/', '_')}.json"

            paths = kv.split("/")

            try:

                if HVAC_BACKUP_PUBLIC_KEY is None:

                    logging.error("!!! Backup file must be encrypted, please provide the encryption key !!!")

                else:

                    vaultManager.export_secrets(paths[0], f"{paths[1]}/", None, output_file, HVAC_BACKUP_PUBLIC_KEY)

                logging.info(f"Secret path '{kv}': hvac export completed.")

            except subprocess.CalledProcessError:

                logging.error(f"Error making API request while exporting {kv}. Please verify hvac is authorized to export secrets.")

              

                exit(1)

          

            if vaultManager.upload_file(os_token, os_object_storage_url, os.environ.get("OPENSTACK_CONTAINER_ACCOUNT"), container, output_file):

                logging.info(f"{kv} has been successfully uploaded to \"{os_object_storage_url}/v1/{os.environ.get('OPENSTACK_CONTAINER_ACCOUNT')}/{container}/{os.path.basename(output_file)}\"")

            else:

                logging.error(f"{kv} export could not be uploaded to {region} {os.environ.get('PROJECT')} ccloud storage. Check if the token and all needed env variables are present.")

                exit(1)

  

        logging.info("Exporting completed successfully!")

      

    # elif args.command == "backup-restore":

    #     if args.destination_address is None:

    #         logging.info("Please provide the Vault Destination Address(Write Address)")

    #     if args.destination_token is None:

    #         logging.info("Please provide the Vault Destination Token(Write Token)")

    #     if args.path is None:

    #         logging.info("Please provide the file path where the back-up is stored")

    #     vaultClient = VaultClient(False, True, None, None, args.destination_address[0], args.destination_token[0])

    #     vaultManager = VaultSecretsManager(vaultClient)

    #     if args.decryption_private_key is not None:

    #         vaultManager.import_secrets(args.path[0], args.decryption_private_key[0])

    #     else:

    #         vaultManager.import_secrets(args.path[0], None)

  

    elif args.command == "sync":

        if args.source_address is None:

            logging.info("Please provide the Vault Source Address(Read Address)")

        if args.source_token is None:

            logging.info("Please provide the Vault Source Token(Read Token)")

        if args.destination_address is None:

            logging.info("Please provide the Vault Destination Address(Write Address)")

        if args.destination_token is None:

            logging.info("Please provide the Vault Destination Token(Write Token)")

        vaultClient = VaultClient(True, True, args.source_address[0], args.source_token[0], args.destination_address[0], args.destination_token[0], None, os.environ.get("VAULT_NAMESPACE"))

        vaultManager = VaultSecretsManager(vaultClient)

        vaultManager.sync()


    else:

        parser.print_help()

  

   

   

if __name__ == "__main__":

    main()