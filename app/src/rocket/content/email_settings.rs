use crate::MAIL_DOMAIN;
pub const SETTINGS:&str = const_format::formatcp!(r#"
<h2>Mail-Settings:</h2>
<h3>IMAP4:</h3>
<p>Mail-Server: {MAIL_DOMAIN}</p>
<p>Port: 993</p>
<p>Security: SSL/TLS</p>
<p>Password-Type: Normal-Password</p>
<p>Username: Your full email-address</p>
<p>Password: Your email-password</p>
<br>
<h3>SMTP:</h3>
<p>Mail-Server: {MAIL_DOMAIN}</p>
<p>Port: 465</p>
<p>Security: SSL/TLS</p>
<p>Username: Your full email-address</p>
<p>Password-Type: Normal/Unencrypted Password</p>
<p>Password: Your email-password</p>
<br>
<h3>POP3:</h3>
<p>Mail-Server: {MAIL_DOMAIN}</p>
<p>Port: 995</p>
<p>Security: SSL/TLS</p>
<p>Password-Type: Normal-Password</p>
<p>Username: Your full email-address</p>
<p>Password: Your email-password</p>
"#);