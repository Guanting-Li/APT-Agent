import mysql.connector

try:
    # Connect to the MySQL server
    connection = mysql.connector.connect(
        host="10.184.42.183",        # Replace with your server's IP address
        user="Will",      # Replace with your MySQL username
        password="toor",# Replace with your MySQL password
        database="apt_agent" # Replace with the name of the database
    )

    # Check if the connection was successful
    if connection.is_connected():
        print("Connected to MySQL server")

        # Create a cursor object to interact with the database
        cursor = connection.cursor()

        # Execute a query
        cursor.execute("SHOW DATABASES;")
        databases = cursor.fetchall()

        # Print the databases
        print("Databases available:")
        for db in databases:
            print(db)

except mysql.connector.Error as err:
    print(f"Error: {err}")

finally:
    # Close the connection
    if 'connection' in locals() and connection.is_connected():
        connection.close()
        print("Connection closed")
