# Part 1 Data Collection and  Part 2 Database Design

# Database Design

This assumes that PostgreSQL database installed on you computer.

## Creating new database

In order to create new postgres database where new data can be stored execute following steps in terminal
```
-- Connect to PostgreSQL
psql -U postgres

-- Create the database
CREATE DATABASE cve;

-- Create the user with a password
CREATE USER postgres WITH PASSWORD 'postgres';

-- Grant all privileges on the database to the user
GRANT ALL PRIVILEGES ON DATABASE cve TO postgres;

-- Exit the psql prompt
\q
```

## Schemas 

Database data model is present in folder [database_creation/schema](https://github.com/anneott/cybercube/tree/main/database_creation/schema).
Database diagram image that gives an understanding of the data model is in file
[database_creation/schema/data_model.png](https://github.com/anneott/cybercube/blob/main/database_creation/schema/data_model.png).


The commands to generate the database schema in postgres are available in [database_creation/schema/postgres_schemas.sql](https://github.com/anneott/cybercube/blob/main/database_creation/schema/postgres_schema.sql).
It includes
* creating tables
* creating foreign keys and references between tables
* creating indexes


Execute the SQL commands in [database_creation/schema/postgres_schemas.sql](https://github.com/anneott/cybercube/blob/main/database_creation/schema/postgres_schema.sql)
to create initial database structure (this step should be automated in the future).

### Indexes

Index is added to each table's `cve_id` column, because that is the column mainly used for joining tables.
More indexes can be added once it is known what columns will be most heavily used.
The primary keys in PostgreSQL already create unique indexes on the id columns, so no need to add indexes there.


# Data Collection

## Populating database

To query all the historical CVE data and save it to our freshly created database
use python script `data_collection.py`. It makes requests to CVE API (https://nvd.nist.gov/developers/vulnerabilities) 
and stores the data in our freshly created database.

Assuming conda enivornment setup step is done execute the following steps:
1. Execute `python main_database_creation.py`
2. Wait until the code finishes execution successfully
3. Verify that database tables are populated with data

