import mysql.connector
from mysql.connector import Error

def connect_to_db():
    """ Connect to MySQL database """
    try:
        conn = mysql.connector.connect(host='localhost',
                                       user="Will",      
                                       password="toor",
                                       database="apt_agent")
        if conn.is_connected():
            print('Connected to MySQL database')
            return conn
    except Error as e:
        print(e)

def insert_exploit(cursor, service, related_module_name, description, rank):
    """ Insert a new record into the exploits table """
    query = "INSERT INTO modules(service, module_name, description, module_rank) VALUES(%s, %s, %s, %s)"
    try:
        cursor.execute(query, (service, related_module_name, description, rank))
        print("Exploit added successfully")
    except Error as e:
        print("Failed to insert record into MySQL table: {}".format(e))

def read_and_load_data():
    service = input("Enter the service to add records for (e.g., ftp, tftp, misc, gather, scanner): ")
    conn = connect_to_db()
    if conn is not None:
        cursor = conn.cursor()
        with open('exploits.txt', 'r') as file:
            lines = file.readlines()
            for line in lines:
                parts = line.split()
                if len(parts) > 2:
                    # Assuming descriptions start at index 5 up to the second-last index
                    description = ' '.join(parts[5:-1])
                    related_module_name = parts[1]
                    rank = parts[3]
                    insert_exploit(cursor, service, related_module_name, description, rank)
        conn.commit()
        cursor.close()
        conn.close()
        print('MySQL connection is closed')

if __name__ == "__main__":
    read_and_load_data()
