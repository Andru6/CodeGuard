# examples/vulnerable.py
user_input = request.args.get("id")
query = "SELECT * FROM users WHERE id = " + user_input
cursor.execute(query)

password = hashlib.md5(user_password.encode()).hexdigest()
