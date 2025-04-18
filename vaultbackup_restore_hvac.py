#!/usr/bin/env python3
import logging
import sys
import os
import json
import argparse
import openstack
import subprocess
import hvac
import base64
from datetime import datetime
import requests
from requests.auth import HTTPBasicAuth
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from cryptography.hazmat.primitives import serialization, hashes

from cryptography.hazmat.primitives.asymmetric import rsa, padding

#CC container Object storage name
CONTAINER = "vault-backup"

#declare an empty dict for the environment variable.
env_vars = {}

# Log function
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

logging.basicConfig(level=LOG_LEVEL)
logger = logging.getLogger(__name__)

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

# fetch and validate required env.variables
def get_env_variables(*required_vars):
    for var in required_vars:
        value = os.getenv(var)
        if value is None:
            raise ValueError(f"Error: Required environment variable '{var}' is not set.")
        env_vars[var] = value

    # Construct URLs based on REGION
    if "REGION" in env_vars:
        env_vars["OS_AUTH_URL"] = f"https://your_os_auth_url.{env_vars['REGION']}"
        env_vars["OS_OBJECT_STORAGE_URL"] = f"https://your_object_storage_url.{env_vars['REGION']}"

    return env_vars

# retrive hvac encryption keys token
def wrap_vault_password(cluster,**env):
    client = hvac.Client(
        url=os.getenv('VAULT_ADDR'),
        token=os.getenv('VAULT_TOKEN'),
    )
    logger.debug(f'HVAC authenticated: {client.is_authenticated()}')
    full_secret_path = f"{env['VAULT_MOUNT_PATH']}/data/your_directory/{cluster}/{env['HVAC_VAULT_SECRET_PATH']}"
    try:
        secret_response = client._adapter.get(
            url=f"/v1/{full_secret_path}",
            wrap_ttl="10m"
        )

        # Extract wrap_info from the api response
        if "wrap_info" in secret_response:
            wrap_info = secret_response["wrap_info"]
            #Response-Wrapping token path validation
            creation_path= wrap_info.get("creation_path")
            if not creation_path or creation_path != full_secret_path:
                raise Exception(f"Invalid creation path: {creation_path}. Possible tampering detected!")
            return wrap_info
        else:
            logger.error("No wrap_info in the wrapped response.")
            return None

    except Exception as e:
        logger.error(f"Error occurred: {e}")
        return None

#retrive secrets from vault
def read_vault_secret(secret_path, cluster):
    client = hvac.Client(
        url=os.getenv('VAULT_ADDR'),
        token=os.getenv('VAULT_TOKEN'),
    )
    logger.debug(f'HVAC authenticated: {client.is_authenticated()}')

    full_secret_path = f'your_directory/{cluster}/{secret_path}'
    try:
        response = client.secrets.kv.v2.read_secret_version(
            mount_point=os.getenv('VAULT_MOUNT_PATH'),
            path=full_secret_path,
            raise_on_deleted_version=True
        )

        if 'data' in response and 'data' in response['data']:
            secret_data = response['data']['data']
            logger.info(f'Retrieved vault secret at path: {full_secret_path}.')
            return secret_data  
            
    except hvac.exceptions.InvalidPath:
        logger.error(f'No secret found at {full_secret_path}.')
    return None

# Function retrieve the auth token
def authenticate_openstack(**env):

    auth_args = {
        "auth_url": env["OS_AUTH_URL"],
        "username": env["STORAGE_USER"],
        "password": env["STORAGE_PASSWORD"], 
        "user_domain_name": env["DOMAIN"],
        "region_name": env["REGION"],
        "project_name": env["PROJECT"],
        "project_domain_name": env["DOMAIN"],
        "verify": False
    }
    
    logger.info('Fetching Openstack Token')
    try:
        client = openstack.connect(**auth_args)
        auth_token = client.auth_token 
        session = client.session  
        logger.info("Acquired OpenStack token Successfully.")
        return auth_token, session  
    except Exception as e:
        logger.error("Fetching Openstack Token failed. Check required credentials.")
        sys.exit(1)

# Function to get object to object versions
def get_object_versions(**env):
    all_latest_files = {}
    most_recent_files = []

    #convert string into list
    vault_secret_paths = env["VAULT_SECRET_PATHS"].split(",")

    for kv in vault_secret_paths:
        kv = kv.replace("/", "_")
        try:
            object_storage_endpoint = f"{env['OS_OBJECT_STORAGE_URL']}/v1/{env['OPENSTACK_CONTAINER_ACCOUNT']}/{CONTAINER}?versions"
            response = session.get(object_storage_endpoint, headers={"X-Auth-Token": auth_token}, verify=False)
    
            if response.status_code == 200:
                files = response.json()
                matching_files = [
                    {"name": file["name"], "last_modified": file["last_modified"]}
                    for file in files if file["name"].endswith(kv + ".json")
                ]
                if matching_files:
                    files_sorted = sorted(
                        matching_files, 
                        key=lambda x: datetime.strptime(x['last_modified'], '%Y-%m-%dT%H:%M:%S.%f'), 
                        reverse=True
                    )
                    # Get latest 5 backup files
                    latest_files = [file["name"] for file in files_sorted[:5]]
                    most_recentfile = files_sorted[0]["name"] if files_sorted else None
                    #logger.info(f"Latest 5 files for {kv} path: {latest_files}")
                    #logger.info(f"Most recent file for {kv} path: {most_recentfile}")
                    all_latest_files[kv] = latest_files 
                    most_recent_files.append(most_recentfile)
                else:
                    logger.info(f"No Vault-backup files found for the condition check for the secret path:{kv}")
            else:
                logger.error(f"No matching files found for '{kv}'.")
        except Exception as e:
            logger.error("Failed to fetch backup file versions. Verify token and storage permissions.")
    return all_latest_files, most_recent_files
        
# Function to download object versions
def download_object_file(**env):

    downloaded_files = [] 
    # Get the latest/user selected file version details using OpenStack Object Storage API
    selected_backupfiles = [env["SELECTED_DIRECTORY_1_BACKUP"].strip('"'), env["SELECTED_DIRECTORY_2_BACKUP"].strip('"')]

    for most_recentfile in selected_backupfiles:
        try:
            object_storage_endpoint = f"{env['OS_OBJECT_STORAGE_URL']}/v1/{env['OPENSTACK_CONTAINER_ACCOUNT']}/{CONTAINER}/{most_recentfile}"
            download_response = session.get(object_storage_endpoint, headers={"X-Auth-Token": auth_token}, stream=False, verify=False)

            #store temporarily in the Jenkins workspace directory. 
            file_path = f"{most_recentfile}"
            logger.info(f"Downloading target backup file '{file_path}' from CCloud.")
                    
            if download_response.status_code == 200:
                with open(file_path, "wb") as f:
                    f.write(download_response.content)  
                    ##download large file size/flexible
                    #for chunk in download_response.iter_content(chunk_size=8192):  # Adjust chunk size if needed
                    #f.write(chunk)
                logger.info(f"Successfully downloaded '{most_recentfile}' to workspace directory {file_path}.")
                downloaded_files.append(file_path)
            else:
                logger.error(f"Failed to download '{most_recentfile}' from CCloud. Status code: {download_response.status_code}")
                return None
        except Exception as e:
            logger.error(f"Failed to download secret file. Error: {str(e)}")
            return None
    return downloaded_files   

# Extracts and returns the modulus hash of a private or public RSA key.
def get_modulus(file, is_private=True):
    cmd = f"openssl rsa -in {file} {'-pubin' if not is_private else ''} -noout -modulus | openssl md5"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout.strip()

# Verifies if the private and public keys belong to the same RSA key pair.
def verify_rsa_keys(private_key_path, public_key_path):
    logger.info("Verifying RSA key pair...")
    modulus_private = get_modulus(private_key_path, is_private=True)
    modulus_public = get_modulus(public_key_path, is_private=False)

    if modulus_private == modulus_public:
        logger.info("RSA Key Pair Valid - Proceed with Hvac import")
        return True
    else:
        logger.error("RSA Key Mismatch - Hvac import Aborted")
        sys.exit(1)
            
            
            
            
def import_secret(path, secret, mount_point, custom_metadata):
    
    client = hvac.Client(
        url=os.getenv('VAULT_ADDR'),
        token=os.getenv('VAULT_TOKEN'),
    )
    if not client.is_authenticated():

        raise ValueError("Vault authentication failed. Check your token.")
    
    client.secrets.kv.v2.create_or_update_secret(

            mount_point = mount_point,

            path = path,

            secret = secret

        )

    client.secrets.kv.v2.update_metadata(

            mount_point = mount_point,

            path = path,

            custom_metadata = custom_metadata

        )
        
        
            
def import_secrets(*import_path, decryption: None):
    
    for file in import_path:

        if decryption is not None:

            rsaDecrypter = RSACrypt(decryption)

            secretsMap = json.loads(rsaDecrypter.decrypt_file(file, None))

            for key in secretsMap:

                import_secret(key, secretsMap[key]["data"], "your_mount_point", secretsMap[key]["metadata"]["custom_metadata"])


        else:

            logging.info("Backups are always encrypted, please provide the decryption key!")

# Test Monitor connection
def test_es_connection(host: str, user: str, password: str) -> None:
    try:
        response = requests.get(host, auth=HTTPBasicAuth(user, password))
        response.raise_for_status()
        logging.info("Connected to Monitor successfully.")
    except requests.exceptions.RequestException as err:
        logging.error("Failed to connect to Monitor: %s", err)
        sys.exit(1)

# Bulk write documents to Monitor.
def write_to_elasticsearch(host: str, user: str, password: str, index: str, docs: list[dict]) -> None:
    bulk_url = f"{host}/{index}/_bulk"
    headers = {"Content-Type": "application/x-ndjson"}

    bulk_data = "\n".join(
        f"{json.dumps({'create': {}})}\n{json.dumps(doc)}" for doc in docs
    ) + "\n"

    try:
        response = requests.post(
            bulk_url, 
            auth=HTTPBasicAuth(user, password), 
            headers=headers, 
            data=bulk_data
        )
        response.raise_for_status()
        logging.info("Successfully inserted %d documents.", len(docs))
        print(response.json())  # Optional: Print response for debugging
    except requests.exceptions.RequestException as err:
        logging.error("Failed to insert documents: %s", err)

# Run the main function
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Retrieve and Restore Hvac backup into the Vault.')
    parser.add_argument('--list_backups', action='store_true', help='Fetch the list of Backup file versions.')
    parser.add_argument('--get_token', action='store_true', help='For the Manual Rollout approach, retrieve the token for the Hvac encryption keys')
    parser.add_argument('--fetch_files', action='store_true', help='Download the user selected backup files & Hvac encryption keys.')
    parser.add_argument('--backup_restore', action='store_true', help='Automatic vault-backup restoration via Hvac cli.')
    parser.add_argument('--send_report', action='store_true', help='send report to Elasticsearch monitor.')
    args = parser.parse_args()

    if args.list_backups or args.fetch_files:
        # Load required environment variables
        required_vars = ["CLUSTERNAME","REGION","PROJECT","DOMAIN","OPENSTACK_CONTAINER_ACCOUNT","STORAGE_USER","VAULT_SECRET_PATHS","VAULT_MOUNT_PATH","HVAC_VAULT_SECRET_PATH"]
        env = get_env_variables(*required_vars)

        # Get openstack storage account details
        secrets = read_vault_secret(env["STORAGE_USER"], env["CLUSTERNAME"])
        if secrets:
            username, password = secrets.get("username"), secrets.get("password")
            logger.info("Successfully retrieved CC openStack storage user auth.")

            # Update env{} to include OpenStack storage user credentials
            env["STORAGE_USER"] = username
            env["STORAGE_PASSWORD"] = password

            # Get OpenStack auth token
            auth_token, session = authenticate_openstack(**env)

            # Update env{} with auth token and session
            env["OS_AUTH_TOKEN"] = auth_token
            env["SESSION"] = session

    if args.list_backups:
        # Get list of objects 
        all_latest_files, most_recent_files= get_object_versions(**env)
        print(json.dumps({"backups_list": all_latest_files, "most_recent": most_recent_files}))

    elif args.fetch_files:
        #Load required environment variable 
        additional_vars = ["SELECTED_DIRECTORY_1_BACKUP","SELECTED_DIRECTORY_2_BACKUP"]
        env.update(get_env_variables(*additional_vars))
    
        #Get the HVAC encryption keys from Vault
        cluster = 'generic'
        secrets = read_vault_secret(env["HVAC_VAULT_SECRET_PATH"], cluster)
        
        #Store temporarily in the Jenkins workspace directory. 
        private_key_path, public_key_path = "private-key.pem", "public-key.pem"

        if secrets:
            try:
                # Base64 decode them for processing.
                private_key_b64, public_key_b64 = secrets.get("private-key.pem"), secrets.get("public-key.pem")
                if private_key_b64 and public_key_b64:
                    private_key = base64.b64decode(private_key_b64).decode()
                    public_key = base64.b64decode(public_key_b64).decode()
                    logger.info("Successfully retrieved and decoded hvac encryption keys.")

                    for path, key in [(private_key_path, private_key), (public_key_path, public_key)]:
                        with open(path, "w") as f:
                            f.write(key)

                    verify_rsa_keys(private_key_path, public_key_path)
                else:
                    logger.error("Missing one or both hvac encryption RSA keys.")
            except Exception as e:
                logger.error(f"Failed to decode base64 hvac encryption RSA keys: {e}")

            file_path=download_object_file(**env)
            print(json.dumps({"backup_files_path": file_path }))
        
    elif args.backup_restore:
        private_key_path= "private-key.pem"
        file_path = os.getenv("BACKUP_FILE_PATHS", "")
        file_path = [item.strip('"') for item in file_path.split(",")]
        import_secrets(*file_path, private_key_path)
        
    # Forward backup-restore workflow reports to Monitor:
    elif args.send_report:
        execution_timestamp = datetime.now().isoformat()

        #Load required environment variable 
        required_vars = ["USER","USER_ID","ES_MONITOR_USER","MONITOR_CLUSTERNAME","ES_MONITOR_HOST_URL","ES_MONITOR_INDEX","BUILD_STATUS","BUILD_URL","START_TIME","MSG","MANUAL_ROLLOUT"]
        env=get_env_variables(*required_vars)
        
        secrets = read_vault_secret(env["ES_MONITOR_USER"], env["MONITOR_CLUSTERNAME"])
        if secrets:
            es_user, es_pass = secrets.get("username"), secrets.get("password")
            logger.info("Successfully retrieved ES monitor ingest user auth.")

        # Test connection
        test_es_connection(env["ES_MONITOR_HOST_URL"], es_user, es_pass)

        #Create workflow logs based on build status
        build_status = env["BUILD_STATUS"]
        #Determine method based on MANUAL_ROLLOUT value
        restore_method = "manual_restore" if env.get('MANUAL_ROLLOUT') == 'true' else "auto_restore"

        # Common fields to initialize the document
        doc = {
            "event": {
                "kind": "workflow",
                "category": ["process"],
                "type": ["backup", "restore", "approval"],
                "created": env['START_TIME'], 
                "action": restore_method,
                "reason": env['MSG']
            },
            "workflow": {
                "name": "Vault-backup Restore",
                "method": restore_method
            },
            "user": {
                "name": env['USER'],
                "id": env['USER_ID']
            },
            "reviewer": {
                "name": os.getenv('APPROVER'),
                "id": os.getenv('APPROVER_ID')
            },
            "ci": {
                "build": {
                    "url": env['BUILD_URL']
                }
            }
        }

        # Handle different build statuses
        if build_status == 'Triggered':
            doc["@timestamp"] = env['START_TIME']
            doc["workflow"]["state"] = "triggered"
            doc["message"] = f"Vault-backup restore workflow triggered by {env['USER']}."
    
        elif build_status == 'SUCCESS':
            doc["workflow"]["state"] = "success"
            doc["@timestamp"] = execution_timestamp
            if env.get('MANUAL_ROLLOUT') == 'true':
                doc["message"] = "Successfully retrieved the shared encryption keys token. The vault-backup restore will be performed manually."
            else:
                doc["message"] = f"Vault-backup restoration completed successfully. Check more details: {env['BUILD_URL']}"

        elif build_status == 'FAILURE':
            doc["@timestamp"] = execution_timestamp
            doc["workflow"]["state"] = "failed"  
            doc["message"] = os.getenv('ERROR') or f"Vault-backup restore workflow failed. Check more details: {env['BUILD_URL']}"

        elif build_status == 'ABORTED':
            doc["@timestamp"] = execution_timestamp
            doc["workflow"]["state"] = "aborted"
            doc["message"] = f"Vault-backup restore workflow was aborted. Check more details: {env['BUILD_URL']}"

        # Write documents to Elasticsearch
        write_to_elasticsearch(env["ES_MONITOR_HOST_URL"], es_user, es_pass, env["ES_MONITOR_INDEX"], [doc])

    elif args.get_token:
        cluster = 'generic'
        #Load required environment variable 
        required_vars = ["HVAC_VAULT_SECRET_PATH","VAULT_MOUNT_PATH"]
        env=get_env_variables(*required_vars)
        wrap_info = wrap_vault_password(cluster,**env)
        if wrap_info:
            print(f"Wrapped Token Details: {wrap_info}")
        else:
            logger.error("Failed to wrap the secret.")