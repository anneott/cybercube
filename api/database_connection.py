import os
import psycopg2
from psycopg2 import pool
import logging
from dotenv import load_dotenv

env_file_path = os.path.join(os.path.dirname(__file__), '..', '.env')
load_dotenv(env_file_path)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def create_connection_pool():
    db_params = {
        'dbname': os.environ.get('POSTGRES_DBNAME'),
        'user':  os.environ.get('POSTGRES_USERNAME'),
        'password':  os.environ.get('POSTGRES_PASSWORD'),
        'host':  os.environ.get('HOST'),
        'port':  os.environ.get('PORT'),
    }
    print(db_params)

    try:
        connection_pool = psycopg2.pool.SimpleConnectionPool(
            1,  # min number of connections
            10, # max number of connections
            **db_params
        )
        if connection_pool:
            logging.info("Connection pool created successfully")

    except psycopg2.DatabaseError as e:
        logging.error(f"Error creating connection pool: {e}")
    return connection_pool