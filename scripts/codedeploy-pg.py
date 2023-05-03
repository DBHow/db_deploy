from sqlite3 import DatabaseError
import sys, os, json, hashlib
import boto3, psycopg2, smtplib
from botocore.exceptions import ClientError
from email.message import EmailMessage
from operator import attrgetter
from datetime import datetime, timezone
from script_file import script_file

# ssm_client = boto3.client('ssm', 'us-east-1')

def send_email(subject, body):
    try:
        smtp_server = os.environ.get("SMTP_SERVER")
        from_address = os.environ.get("FROM_ADDRESS")
        to_address = os.environ.get("TO_ADDRESS")

        if smtp_server is None or from_address is None or to_address is None:
            raise Exception("Can't send email because of invalid parameters")
        
        msg = EmailMessage()
        msg.set_content(body)
        msg['Subject'] = subject
        msg['From'] = from_address
        msg['To'] = to_address
        with smtplib.SMTP(smtp_server) as smtp:
            smtp.send_message(msg)
            
    except Exception as e:
        print(str(e))

def get_secret(name):
    # Creates a secrets manager client
    session = boto3.session.Session()
    client = session.client('secretsmanager', 'us-east-1')

    try:
        response = client.get_secret_value(
            SecretId = name
        )
    except ClientError as e:
        raise e

    # Decrypts secret using the associated KMS key
    secret = json.loads(response["SecretString"])
    return secret

def hashfile(file):
    BUF_SIZE = 65536

    # Initializing the sha256() method
    sha256 = hashlib.sha256()

    with open(file, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)

            #True if eof = 1
            if not data:
                break

            # Passing the data to that sha256 hash function
            sha256.update(data)

    # Hashes all the input data and returns the output in hex format
    return sha256.hexdigest()

def main(dir_name, deploy_file_name):
    dsn = None
    script_files = [] 
    f = None
    
    try:
        deploy_name = os.path.join(dir_name, deploy_file_name)

        # Parses the json deploy file 
        # Retrieves information from parameter store
        # Loads data to script_file class
        f = open(deploy_name, encoding='utf-8')
        deploy_metadata = json.load(f)

        project = deploy_metadata.get('project')
        version = deploy_metadata.get('version')
        description = deploy_metadata.get('description')
        secret_name = deploy_metadata.get('targetDatabaseSecret')
        print(f'Extracted information from {deploy_file_name}')
        
        # Retrieves connection information from secrets manager
        secret = get_secret(secret_name)
        host = secret['host']
        port = secret['port']
        database = secret['database']
        username = secret['username']
        password = secret['password']
        dsn = f'host={host} port={port} dbname={database} user={username} password={password}'
        print(f'Retrieved connection information from secrets manager')

        # Processes the script files
        files = deploy_metadata.get('files')  

        for file in files:
            filepath = os.path.join(dir_name, file['name'])
            if not os.path.isfile(filepath):
                raise FileNotFoundError(filepath)

            script_files.append(script_file(file['name'], file['order'], file['description'], filepath))

        print(f'Number of files to be deployed: {len(script_files)}')
        script_files.sort(key=attrgetter('order', 'name'))
    except Exception as e:
        msg = f'Error in processing deploy metadata file {deploy_file_name}: {e}'
        print(msg)
        send_email(f'Error in process {deploy_file_name}', msg)
    finally:
        if f is not None:
            f.close()

    if dsn is not None and len(script_files) > 0:
        # Creates a record for this deployment
        insert_deployment = 'INSERT INTO dba_admin.deployments (project, version, description, start_time) VALUES (%s, %s, %s, %s)'
        update_deployment = 'UPDATE dba_admin.deployments SET end_time = %s, status = %s WHERE project = %s AND version = %s'
        check_existence = 'SELECT count(*) FROM dba_admin.deployment_files WHERE project = %s AND version = %s and hash_value = %s'
        insert_deployment_file = 'INSERT INTO dba_admin.deployment_files (project, version, filename, description, hash_value, deploy_time) VALUES (%s, %s, %s, %s, %s, %s)'
        
        conn = None
        
        try:
            conn = psycopg2.connect(dsn)
            cur = conn.cursor()

            # Log the start of deployment
            cur.execute(insert_deployment, (project, version, description, datetime.now(timezone.utc)))
            conn.commit()
            print(f'Starting the deployment...')

            status = 'succeeded'
            current_file = None
            
            try:
                for file in script_files:
                    current_file = file.name
                    hash_value = hashfile(file.filepath)

                    # Execute the script file
                    cur.execute(open(file.filepath).read())
                    print(f'Deployed {current_file}')
                    
                    # Log the deployment of the file
                    cur.execute(insert_deployment_file, (project, version, file.name, file.description, hash_value, datetime.now(timezone.utc)))
                    
                conn.commit()
            except (Exception, psycopg2.DatabaseError) as err:
                conn.rollback()
                status = f'Failed to deploy {current_file}: {err}'
                
            # Log the end of deployment
            cur.execute(update_deployment, (datetime.now(timezone.utc), status, project, version))
            print(f'Finishing the deployment...')
            conn.commit()

            if status == 'succeeded':
                send_email(f'Succeeded to deploy {project}-{version}', f'')
            else:
                send_email(f'Error in deploying {project}-{version}', f'{status}')
        except (Exception, psycopg2.DatabaseError) as error:
            conn.rollback()
            print(error)
            send_email(f'Error in deploying {project}-{version}', f'{error}')
        finally:
            if conn is not None:
                conn.close()

if __name__ == "__main__":
    if len(sys.argv) == 3:
        main(sys.argv[1], sys.argv[2])
    else:
        raise ValueError('Invalid arguments')


  
