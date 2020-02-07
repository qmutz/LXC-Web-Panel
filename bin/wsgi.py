from pantry.config import read_config_file
from pantry.app import app
#import logging


if __name__ == "__main__":
    #gunicorn_logger = logging.getLogger('gunicorn.error')
    #app.logger.handlers = gunicorn_logger.handlers
    #app.logger.setLevel(gunicorn_logger.level)
    config = read_config_file()
    #app.config['DEBUG'] = True
    app.run(host=app.config['ADDRESS'], port=app.config['PORT'])

