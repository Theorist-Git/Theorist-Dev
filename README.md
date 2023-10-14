# Theorist-Tech Website

## Usage
* Run the website: (Linux systems)
```bash
$ git clone https://github.com/Theorist-Git/Theorist-Dev.git
$ git branch dev 
$ chmod +x make_env.sh
$ ./make_env.sh
```

Then navigate to:
http://127.0.0.1:5000/
. You can change the port in main.py file.
* main.py file has logging already configured, defaults to INFO. Also, the file provides two functions,
namely :
  * run_dev_server(): Runs the flask development server, DO NOT use for production environment.
  * run_prod_server(): Runs the waitress WSGI server, suitable for production environment.

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License
See license.txt