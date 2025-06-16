# users.py

class User():
    def __init__(self, username):
        self.username = username
        self.id = None
        self.logged_in = False
        
        self.groups = set() # The groups that the user belonged to
        self.rights = set()

    def log_in(self, sample) -> bool:
        # This function is used to perform login of user objects. 
        # The return value hints whether the password provided 
        # enabled the user to log in successfully.
        return False