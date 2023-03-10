from django.conf import settings
import os

def getExamplePath(filename):
    return os.path.join(settings.EXAMPLES_DIR, filename)