"""
Copyright (C) 2021 Mayank Vats
See license.txt
"""
import secrets


class OTPMethods:
    # Getting systemRandom class instance out of the secrets module
    secrets_generator = secrets.SystemRandom()

    @staticmethod
    def return_random(otp_len=6):
        """
        Used to generate Random ONE-TIME-PASSWORDS which are
        utilized in the app for user verification and authentication.
        Gets SystemRandom class instance out of secrets module and
        generates a random integer in range [a, b].

        :return: str(random integer in range [100000, 999999])
        """
        # secure random integer numbers
        l_range = (10 ** (otp_len - 1))
        h_range = (l_range * 10) - 1
        otp = OTPMethods.secrets_generator.randint(l_range, h_range)
        return str(otp)


class ElectronicMail:

    @staticmethod
    def sendmail(email, subject, note, role="user"):
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText
        import smtplib

        # create message object instance
        msg = MIMEMultipart()

        if role == "admin":
            message = f"Feedback from user: \n {note}"
        else:
            message = f"Your OTP: {note}"

        # setup the parameters of the message
        password = "yourpass"
        msg['From'] = "youremail"
        msg['To'] = email
        msg['Subject'] = subject

        # add in the message body
        msg.attach(MIMEText(message, 'plain'))

        # create server
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)

        # Login Credentials for sending the mail
        server.login(msg['From'], password)
        # send the message via the server.
        server.sendmail(msg['From'], msg['To'], msg.as_string())
        server.quit()


class CryptographyMethods:
    class Hashing:

        @staticmethod
        def generate_password_hash(password, method: str = "argon2id"):
            supported_hash_methods = [
                "argon2id"
            ]
            if method == "argon2id":
                from argon2 import PasswordHasher
                crypt_er = PasswordHasher()
                return crypt_er.hash(password)
            else:
                return f"We don't support '{method}' method yet. \n" \
                       f"Here are the supported methods : {supported_hash_methods}"

        @staticmethod
        def check_password_hash(secret, password):
            if "$argon" in secret:
                from argon2 import PasswordHasher, exceptions
                crypt_er = PasswordHasher()
                try:
                    return crypt_er.verify(secret, password)
                except exceptions.VerifyMismatchError:
                    return False
            else:
                raise TypeError("Unsupported Hash-Type")


class Misc:

    @staticmethod
    def capitalize_list(lst):
        capitalized_lst = []
        for j in lst:
            capitalized_lst.append(str(j).upper())
        return capitalized_lst
