from functools import wraps
from flask import session,abort,render_template
from werkzeug.utils import redirect


def is_logged_in(f):
    @wraps(f)
    def decorated_function(*args, **kws):
            if session.get('username')==None:
                return render_template('login.html')

            return f(*args, **kws)            
    return decorated_function

def is_admin(f):
    @wraps(f)
    def decorated_function(*args, **kws):
            if session.get('role')!='Admin':
                return redirect('/users')
                
            return f(*args, **kws)            
    return decorated_function

def query_to_dict(ret):
    if ret is not None:
        return [{key: value for key, value in row.items()} for row in ret if row is not None]
    else:
        return [{}]