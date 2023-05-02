from sqlite3 import DatabaseError
import sys, os, json, hashlib
import boto3, psycopg2
from operator import attrgetter
from datetime import datetime, timezone
from script_file import script_file

ssm_client = boto3.client('ssm', 'us-east-1')

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

    # Hashes all the input data and returns the output in
    # hex format
    return sha256.hexdigest()

def main(dir_name, deploy_file_name):
    if not os.path.isdir(dir_name):
        raise NotADirectoryError(dir_name)

    deploy_name = os.path.join(dir_name, deploy_file_name)
    if not os.path.isfile(deploy_name):
        raise FileNotFoundError(deploy_file_name)

    # Parses the json deploy file 
    # Retrieves information from parameter store
    # Loads data to script_file class
    with open(deploy_name, encoding='utf-8') as f:
        deploy_metadata = json.load(f)

        project = deploy_metadata.get('project')
        version = deploy_metadata.get('version')
        description = deploy_metadata.get('description')
        username_path = deploy_metadata.get('usernamePath')
        password_path = deploy_metadata.get('passwordPath')
        host = deploy_metadata.get('targetHost')
        database = deploy_metadata.get('targetDatabase')
        
        # Retrieves username/password from parameter store
        response = ssm_client.get_parameter(Name=username_path, WithDecryption=False)
        username = response['Parameter']['Value']
        response = ssm_client.get_parameter(Name=password_path, WithDecryption=True)
        password = response['Parameter']['Value']
        print(f'Retrieved username/password from parameter store')
        
        # Creates a record for this deployment
        insert_deployment = 'INSERT INTO dba_admin.deployments (project, version, description, start_time) VALUES (%s, %s, %s, %s)'
        update_deployment = 'UPDATE dba_admin.deployments SET end_time = %s WHERE project = %s AND version = %s'
        check_existence = 'SELECT count(*) FROM dba_admin.deployment_files WHERE project = %s AND version = %s and hash_value = %s'
        insert_deployment_file = 'INSERT INTO dba_admin.deployment_files (project, version, filename, description, hash_value, deploy_time) VALUES (%s, %s, %s, %s, %s, %s)'
        dsn = f'host={host} port=5432 dbname={database} user={username} password={password}'

        conn = None
        
        try:
            conn = psycopg2.connect(dsn)
            cur = conn.cursor()

            # Log the start of deployment
            cur.execute(insert_deployment, (project, version, description, datetime.now(timezone.utc)))
            print(f'Starting the deployment...')
            
            files = deploy_metadata.get('files')
            script_files = []    

            for file in files:
                filepath = os.path.join(dir_name, file['name'])
                if not os.path.isfile(filepath):
                    raise FileNotFoundError(filepath)

                script_files.append(script_file(file['name'], file['order'], file['description'], filepath))

            print(f'Number of files to be deployed: {len(script_files)}')
            script_files.sort(key=attrgetter('order', 'name'))

            for file in script_files:
                hash_value = hashfile(file.filepath)

                # Execute the script file
                cur.execute(open(file.filepath, 'r').read())
                print(f'Deployed {file.name}')

                # Log the deployment of the file
                cur.execute(insert_deployment_file, (project, version, file.name, file.description, hash_value, datetime.now(timezone.utc)))
                print(f'Recorded the deployment of {file.name}')

            # Log the end of deployment
            cur.execute(update_deployment, (datetime.now(timezone.utc), project, version))
            print(f'Finishing the deployment...')
            conn.commit()
            
        except (Exception, psycopg2.DatabaseError) as error:
            conn.rollback()
            print(error)
        finally:
            if conn is not None:
                conn.close()

if __name__ == "__main__":
    if len(sys.argv) == 3:
        main(sys.argv[1], sys.argv[2])
    else:
        raise ValueError('Invalid arguments')


  
