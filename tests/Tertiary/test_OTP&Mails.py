"""
Copyright (C) 2021 Mayank Vats
See license.txt
"""
from website import tert


def test_otp_mails():
    """
    GIVEN instances of OTPMethods and ElectronicMail
    WHEN initialization is done and mail is sent
    THEN check:
            i)   if initialization was successful
            ii)  if server is_active (i.e server status == 205)
            iii) if OTP generated only has integer character
            iv)  if server is not active after email is sent to bdickus172@gmail.com
    """
    rn_jesus = tert.OTPMethods
    postman = tert.ElectronicMail
    initialization = False
    if rn_jesus and postman:
        initialization = True
    assert initialization is True
    assert postman.is_active(postman.server) is True
    comp_otp = rn_jesus.return_random(otp_len=6)
    assert comp_otp.isalpha() is not True
    postman.sendmail("bdickus172@gmail.com", "pytest running...", comp_otp)
    assert postman.is_active(postman.server) is False


def test_misc():
    """
    GIVEN an instance of Misc and a lst with no capital characters
    WHEN the aforementioned list is capitalized (see tert.py)
    THEN check if all the elements are capital.
    """
    capitalizer = tert.Misc
    lst = ['january', 'february', 'march', 'april', 'may', 'june', 'july', 'august', 'september', 'october', 'november',
           'december']
    cap_lst = capitalizer.capitalize_list(lst)
    for i in cap_lst:
        if i.isalpha():
            assert i.isupper() is True
