"""
Copyright (C) Mayank Vats - All Rights Reserved
Unauthorized copying of any file, via any medium is strictly prohibited
Proprietary and confidential
Written by Mayank Vats <dev-theorist.e5xna@simplelogin.com>, 2021-2022
"""

import sys

sys.path.append('C:\\Users\\mayan\\Desktop\\languages\\Python 3.9\\Projects\\WebDev\\Flask\\Citadel')

from __init__ import create_app
import logging
# from waitress import serve

app = create_app()

"""
    Logger logs INFO, WARNINGS, ERROR and CRITICAL logs to 'filename'
    Set the log level to anyone of the following
    
    P.S: cd to project/content root of your project and then paste : pytest -v -W ignore::DeprecationWarning
    to run the tests configured.
"""

logging.basicConfig(filename='WebRecord.log', level=logging.INFO,
                    format='%(asctime)s - %(threadName)s - %(name)s - %(levelname)s - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')

if __name__ == '__main__':
    print("Running at http://127.0.0.1:5000/ \n Copyright (C) 2021-2022 Mayank Vats")

    def run_dev_server():
        """
        Use only for development purposes, call run_prod_server() when in
        production. The server runs with re-loader by default.
        """
        print('\033[1m', 'DEVELOPMENT SERVER', '\033[0m')
        app.run(debug=True, use_reloader=True, port=5000, host='0.0.0.0')


    # def run_prod_server():
    #     """
    #     Production wsgi server, waitress is used to serve. Debug is False
    #     by default.
    #     """
    #     app.debug = False
    #     print('\033[1m', 'PRODUCTION SERVER', '\033[0m')
    #     serve(app, listen='127.0.0.1:5000', threads=10)

    run_dev_server()
