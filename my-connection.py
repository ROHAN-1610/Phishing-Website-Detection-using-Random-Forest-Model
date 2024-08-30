import  mysql.connector as MyConn

mydb=MyConn.connect(host="localhost",user="root",password="mysqlpassword",database="trial")
db_cursor=mydb.cursor()

db_cursor.execute("insert into work(name,department) values(%s,%s)",('Aryan','CY'))
mydb.commit()
print(db_cursor.rowcount,"Record inserted")