"""
Copyright (C) Mayank Vats - All Rights Reserved
Unauthorized copying of any file, via any medium is strictly prohibited
Proprietary and confidential
Written by Mayank Vats <dev-theorist.e5xna@simplelogin.com>, 2021-2022
"""


class ElectronicMail:

    @staticmethod
    def sendmail(receiver, subject, note, use_case="mfalogin"):
        from email.message import EmailMessage
        import smtplib
        content = {
            "mfalogin": [
                "Theorist-Tech Two-Factor-Authentication Code:",
                f"You OTP is: {note}",
                "If you didn't attempt this login, someone has your account details, change them immediately:",
                ["https://github.com/Theorist-Git/", "Change-Password"]
            ],
            "registration": [
                "Theorist-Tech Registration Code:",
                f"You OTP is: {note}",
                """If you didn't attempt this registration, you can safely ignore this email, someone might have typed 
it in by mistake""",
                ["https://github.com/Theorist-Git/", "See Latest Projects and Blogs"]
            ],
            "Enable_2FA": [
                "Theorist-Tech Enabling 2FA",
                f"You OTP is: {note}",
                "If you didn't attempt this, someone has your account details, change them immediately:",
                ["https://github.com/Theorist-Git/", "Change-Password"]
            ],
            "PassReset": [
                "Theorist-Tech Password-Reset",
                f"You OTP is: {note}",
                """If you didn't attempt this password-reset, you can safely ignore this email, someone might have typed 
it in by mistake""",
                ["https://github.com/Theorist-Git/", "Change-Password"]
            ]
        }
        # create message object instance
        msg = EmailMessage()

        # setup the parameters of the message
        password = "==="
        msg['From'] = "==="
        msg['To'] = receiver
        msg['Subject'] = subject

        # add in the message body
        msg.set_content("""
        <!doctype html>
<html>
  <head>
    <meta name="viewport" content="width=device-width">
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <style>
    /* -------------------------------------
        INLINED WITH htmlemail.io/inline
    ------------------------------------- */
    /* -------------------------------------
        RESPONSIVE AND MOBILE FRIENDLY STYLES
    ------------------------------------- */
    @media only screen and (max-width: 620px) {
      table[class=body] h1 {
        font-size: 28px !important;
        margin-bottom: 10px !important;
      }
      table[class=body] p,
            table[class=body] ul,
            table[class=body] ol,
            table[class=body] td,
            table[class=body] span,
            table[class=body] a {
        font-size: 16px !important;
      }
      table[class=body] .wrapper,
            table[class=body] .article {
        padding: 10px !important;
      }
      table[class=body] .content {
        padding: 0 !important;
      }
      table[class=body] .container {
        padding: 0 !important;
        width: 100% !important;
      }
      table[class=body] .main {
        border-left-width: 0 !important;
        border-radius: 0 !important;
        border-right-width: 0 !important;
      }
      table[class=body] .btn table {
        width: 100% !important;
      }
      table[class=body] .btn a {
        width: 100% !important;
      }
      table[class=body] .img-responsive {
        height: auto !important;
        max-width: 100% !important;
        width: auto !important;
      }
    }

    /* -------------------------------------
        PRESERVE THESE STYLES IN THE HEAD
    ------------------------------------- */
    @media all {
      .ExternalClass {
        width: 100%;
      }
      .ExternalClass,
            .ExternalClass p,
            .ExternalClass span,
            .ExternalClass font,
            .ExternalClass td,
            .ExternalClass div {
        line-height: 100%;
      }
      .apple-link a {
        color: inherit !important;
        font-family: inherit !important;
        font-size: inherit !important;
        font-weight: inherit !important;
        line-height: inherit !important;
        text-decoration: none !important;
      }
      #MessageViewBody a {
        color: inherit;
        text-decoration: none;
        font-size: inherit;
        font-family: inherit;
        font-weight: inherit;
        line-height: inherit;
      }
      .btn-primary table td:hover {
        background-color: #34495e !important;
      }
      .btn-primary a:hover {
        background-color: #34495e !important;
        border-color: #34495e !important;
      }
    }
    </style>
  </head>"""
                        +

                        f"""
   <body class="" style="background-color: #f6f6f6; font-family: sans-serif; -webkit-font-smoothing: antialiased; 
   font-size: 14px; line-height: 1.4; margin: 0; padding: 0; -ms-text-size-adjust: 100%; 
   -webkit-text-size-adjust: 100%;">
    <span class="preheader" style="color: transparent; display: none; height: 0; max-height: 0; max-width: 0; opacity:
     0; overflow: hidden; mso-hide: all; visibility: hidden; width: 0;">{content[use_case][0]}</span>
    <table role="presentation" border="0" cellpadding="0" cellspacing="0" class="body" style="border-collapse: 
    separate; mso-table-lspace: 0pt; mso-table-rspace: 0pt; width: 100%; background-color: #f6f6f6;">
      <tr>
        <td style="font-family: sans-serif; font-size: 14px; vertical-align: top;">&nbsp;</td>
        <td class="container" style="font-family: sans-serif; font-size: 14px; vertical-align: top; display: block; 
        Margin: 0 auto; max-width: 580px; padding: 10px; width: 580px;">
          <div class="content" style="box-sizing: border-box; display: block; Margin: 0 auto; max-width: 
          580px; padding: 10px;">

            <!-- START CENTERED WHITE CONTAINER -->
            <table role="presentation" class="main" style="border-collapse: separate; mso-table-lspace: 0pt; 
            mso-table-rspace: 0pt; width: 100%; background: #ffffff; border-radius: 3px;">

              <!-- START MAIN CONTENT AREA -->
              <tr>
                <td class="wrapper" style="font-family: sans-serif; font-size: 14px; vertical-align: top; box-sizing: 
                border-box; padding: 20px;">
                  <table role="presentation" border="0" cellpadding="0" cellspacing="0" style="border-collapse: 
                  separate; mso-table-lspace: 0pt; mso-table-rspace: 0pt; width: 100%;">
                    <tr>
                      <td style="font-family: sans-serif; font-size: 14px; vertical-align: top;">
                        <p style="font-family: sans-serif; font-size: 14px; font-weight: normal; margin: 0; 
                        Margin-bottom: 15px;">Greetings, Traveller</p>
                        <p style="font-family: sans-serif; font-size: 14px; font-weight: normal; margin: 0;
                         Margin-bottom: 15px;">{content[use_case][1]}</p>
                        <table role="presentation" border="0" cellpadding="0" cellspacing="0" class="btn btn-primary" 
                        style="border-collapse: separate; mso-table-lspace: 0pt; mso-table-rspace: 0pt; width: 100%; 
                        box-sizing: border-box;">
                          <tbody>
                            <tr>
                              <td align="left" style="font-family: sans-serif; font-size: 14px; vertical-align: top; 
                              padding-bottom: 15px;">
                                <table role="presentation" border="0" cellpadding="0" cellspacing="0" 
                                style="border-collapse: separate; mso-table-lspace: 0pt; mso-table-rspace: 0pt; 
                                width: auto;">
                                  <tbody>
                                    <tr>
                                    </tr>
                                  </tbody>
                                </table>
                              </td>
                            </tr>
                          </tbody>
                        </table>
                        <p style="font-family: sans-serif; font-size: 14px; 
                        font-weight: normal; margin: 0; Margin-bottom: 15px;
                         ">{content[use_case][2]}</p>
                    </tr>
                  </table>
                </td>
              </tr>
              <td style="font-family: sans-serif; font-size: 14px; vertical-align: top; background-color: #3498db; 
              border-radius: 5px; text-align: center;"> <a href={content[use_case][3][0]} target="_blank" 
              style="display: inline-block; color: #ffffff; background-color: #3498db; border: solid 1px #3498db; 
              border-radius: 5px; box-sizing: border-box; cursor: pointer; text-decoration: none; font-size: 
              14px; font-weight: bold; margin: 0; padding: 12px 25px; text-transform: capitalize; border-color: 
              #3498db;">{content[use_case][3][1]}</a> </td>

            <!-- END MAIN CONTENT AREA -->
            </table>

            <!-- START FOOTER -->
            <div class="footer" style="clear: both; Margin-top: 10px; text-align: center; width: 100%;">
              <table role="presentation" border="0" cellpadding="0" cellspacing="0" style="border-collapse: separate; 
              mso-table-lspace: 0pt; mso-table-rspace: 0pt; width: 100%;">
                <tr>
                  <td class="content-block" style="font-family: sans-serif; vertical-align: top; padding-bottom: 10px; 
                  padding-top: 10px; font-size: 12px; color: #999999; text-align: center;">
                    <span class="apple-link" style="color: #999999; font-size: 12px; text-align: center;">
                    Theorist-Tech</span>
                    <br> This email was auto generated, please do not reply.
                  </td>
                </tr>
                <tr>
                  </td>
                </tr>
              </table>
            </div>
            <!-- END FOOTER -->

          <!-- END CENTERED WHITE CONTAINER -->
          </div>
        </td>
        <td style="font-family: sans-serif; font-size: 14px; vertical-align: top;">&nbsp;</td>
      </tr>
    </table>
  </body>
</html>"""
                        , subtype="html")

        # create server
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)

        # Login Credentials for sending the mail
        server.login(msg['From'], password)
        # send the message via the server.
        server.sendmail(msg['From'], msg['To'], msg.as_string())
        server.quit()


class Misc:

    @staticmethod
    def capitalize_list(lst):
        """
        Capitalizes every element in a list if its a string.

        :param lst: an object of type === <class 'list'>
        :return: A list with every element capitalized.
        """
        capitalized_lst = []
        for j in lst:
            capitalized_lst.append(str(j).upper())
        return capitalized_lst
