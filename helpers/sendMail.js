const nodemailer = require('nodemailer');
const { SMTP_MAIL, SMTP_PASSWORD } = process.env;

const sendMail = async(email, mailSubject, content) => {

    try {

        const transporter = nodemailer.createTransport({
            service: 'gmail',
            // host: "smtp.gmail.com",
            // port: 465,
            // secure: false,
            // requireTLS: true,
            auth: {
                // type: 'login',
                user: SMTP_MAIL,
                pass: SMTP_PASSWORD
            }
        })


        const mailOptions = {

            from: SMTP_MAIL,
            to: email,
            subject: mailSubject,
            html: content
        }

        transporter.sendMail(mailOptions, function(error, info) {
            if (error) {
                console.log(error);
            } else {
                console.log('Mail sent successfully: -', info.response);

            }
        })

    } catch (error) {
        console.log(error.message);

    }

}

module.exports = sendMail;