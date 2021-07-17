import psycopg2
from validators.exceptions.DatabaseException import DatabaseException
class DatabaseAdapter:
    def __init__(self):
        self.username = 'postgres'
        self.password = 'tudor123'
        self.dbname = 'portscanner_information'

        self.connection = psycopg2.connect(host="127.0.0.1",user=self.username,password=self.password,dbname=self.dbname)
        self.connection_cursor = self.connection.cursor()

    def getAllPortInfo(self,port):
        prep_statememnt = """SELECT id FROM ports WHERE port_number = %s"""
        self.connection_cursor.execute(prep_statememnt,[port])
        port_id = self.connection_cursor.fetchone()
        prepared_statement = """SELECT type,description FROM ports_info WHERE port_id = %s"""
        self.connection_cursor.execute(prepared_statement,[port_id])
        return self.connection_cursor.fetchall()

    def logIn(self,username,password):
        prepared_statement = """SELECT username,password FROM users WHERE username = %s and password = %s"""
        prepared_tuple = (username, password)
        self.connection_cursor.execute(prepared_statement,prepared_tuple)
        return (username,password) == self.connection_cursor.fetchone()

    def registerCheck(self,username):
        try:
            prepared_statement = """SELECT username FROM users WHERE username = %s"""
            prepared_tuple = [username]
            self.connection_cursor.execute(prepared_statement, prepared_tuple)
            return username == self.connection_cursor.fetchone()[0]
        except:
            raise DatabaseException("Username not found!")

    def registerUser(self, username, password):
        prepared_statement ="""INSERT INTO users (username,password) VALUES (%s, %s)"""
        prepared_tuple = (username,password)
        self.connection_cursor.execute(prepared_statement, prepared_tuple)
        self.connection.commit()
