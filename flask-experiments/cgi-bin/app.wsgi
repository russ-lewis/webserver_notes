APP_DIR = "/home/ec2-user/flask-experiments/cgi-bin"

# add the CGI directory to the python import path (so that we can
# import the application below)
import sys
sys.path.insert(0, APP_DIR)

# chdir to the CGI directory, so that when we open local config files,
# we'll also get the right files.
import os
os.chdir(APP_DIR)

# now, actually import the application
from flask_experiments import app as application

