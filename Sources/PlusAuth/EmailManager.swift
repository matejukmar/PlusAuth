import Foundation
import PerfectSMTP

var emailConfig: EmailConfig {
	return PlusAuth.shared.emailConfig
}

class EmailManager {
	class func sendVerifyAccountEmail(emailAddress: String, token: String) throws {
		let email = EMail(client: emailConfig.smtpClient)
		email.subject = "Verify email"
		email.from = Recipient(name: emailConfig.fromName, address: emailConfig.fromEmail)
		
		let recoverLink = "\(emailConfig.verifyAccountBaseUrl)?token=\(token)"
		
		email.html = "Dear iSum user, <br />" +
			"please click on this link to verify your account: <br />" +
		"<a href=\"\(recoverLink)\">\(recoverLink)</a>"
		
		email.to.append(Recipient(name: emailAddress, address: emailAddress))
		
		try email.send(completion: { (code, header, body) in
			print(code)
			print(header)
			print(body)
		})
	}

	class func sendForgottenPasswordEmail(emailAddress: String, token: String) throws {
		
		let email = EMail(client: emailConfig.smtpClient)
		email.subject = "Recover password"
		email.from = Recipient(name: emailConfig.fromName, address: emailConfig.fromEmail)
		
		let recoverLink = "\(emailConfig.resetPasswordBaseUrl)?token=\(token)"

		email.html = "Dear iSum user, <br />" +
			"please click on this link to reset your password: <br />" +
			"<a href=\"\(recoverLink)\">\(recoverLink)</a>"

		email.to.append(Recipient(name: emailAddress, address: emailAddress))
		
		try email.send(completion: { (code, header, body) in
			print(code)
			print(header)
			print(body)
		})
	}
}
