from django.core.management import utils

def get_secret_from_file(path):
    try:
        with open(path, "r") as f:
            return f.read().strip()
    except EnvironmentError:
        with open(path, "w") as f:
            secret_key = utils.get_random_secret_key()
            f.write(secret_key)
            return secret_key
