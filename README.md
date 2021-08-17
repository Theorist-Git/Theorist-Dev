# Citadel Website

* Citadel is a website/Blog, where you can post about your coding projects and also collaborate with other developers.
The website has been made using Flask framework. User authentication is managed with the help of [flask-login](https://flask-login.readthedocs.io/en/latest/).
Passwords are hashed and checked with [werkzeug.security](https://werkzeug.palletsprojects.com/en/2.0.x/utils/).
Hashing algorithm used is pbkdf2:sha256 (101000 rounds). CSRF tokens are managed using Flask-WTF, CSRF protection is enabled globally.
* [TinyMCE](https://www.tiny.cloud/) is used as the WYSIWYG editor. Installation details below. The editor automatically manages XSS attacks by escaping script characters.
* [DevBlog v1.3](https://themes.3rdwavemedia.com/bootstrap-templates/personal/devblog-free-bootstrap-4-blog-template-for-developers/)
is used as the template for the blog index.
## Dependencies

1. **Use the package manager [pip](https://pip.pypa.io/en/stable/) to install the python modules required.**

```bash
$ pip install requirements.txt
```
* **This will install all the packages that you lack. It is highly recommended that you work on this project in a virtualenv.**
```bash
$ pip install virtualenv
```
```bash
$ mkvirtualenv myenv
```
```bash
$ workon myenv
```
```bash
(myenv) $ pip install requirements.txt
```
2. **TinyMCE:**
* All the required packages are already a part of this repository, they're in the plugin folder. If you are 
unclear on its usage follow this [guide](https://dyclassroom.com/tinymce/how-to-setup-tinymce-text-editor).
3. **DevBlog v1.3:**
* It can be downloaded from the link given in the beginning of the README. All the required files are already in assets folder.

## Installation
* Use the link to install .zip of the master branch

* [master.zip](https://github.com/Theorist-Git/FlaskCRUD/archive/refs/heads/master.zip)
* To clone the repository:
```bash
git clone <repo-url>
```
## Usage
* Once all the packages are installed, open main.py and run it.
Then navigate to:
http://127.0.0.1:5000/
. You can change the port in main.py file.
* main.py file has logging already configured, defaults to INFO. Also, the file provides two functions,
namely :
  * run_dev_server(): Runs the flask development server, DO NOT use for production environment.
  * run_prod_server(): Runs the waitress WSGI server, suitable for production environment.

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.
Submit a pull request if and only if the pre-written tests aer passed.

## Testing
cd to project/content root of your project and then paste:
```bash
$ pytest -v -W ignore::DeprecationWarning
```
For more information see **/tests directory and conftest.py**

## Authors and acknowledgment
* Author(s): This entire project was coded by [Theorist](https://github.com/Theorist-Git).
* Acknowledgments:
1. [CodeWithHarry](https://www.youtube.com/channel/UCeVMnSShP_Iviwkknt83cww): From where I learnt flask basics
2. [Xiaoying Riley](http://themes.3rdwavemedia.com/): The template for BlogIndex.html file
3. [TinyMCE](https://www.tiny.cloud/): WYSIWYG editor


## License
See license.txt