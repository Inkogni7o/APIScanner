import os
import pickle
def execute(command):
    return os.system(command)

def unused(data):
    return pickle.loads(data)
