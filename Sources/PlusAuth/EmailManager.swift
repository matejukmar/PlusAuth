import Foundation
import PerfectSMTP

var emailConfig: EmailConfig {
	return PlusAuth.shared.emailConfig
}

class EmailManager {
	class func sendVerifyAccountEmail(emailAddress: String, token: String, name: String) throws {
		let email = EMail(client: emailConfig.smtpClient)
		email.subject = "Verify email"
		email.from = Recipient(name: emailConfig.fromName, address: emailConfig.fromEmail)
		
		let link = "\(emailConfig.verifyAccountBaseUrl)?token=\(token)"
		
		email.html = emailConfig.verifyAccountEmailTemplate.stringByReplacing(string: "[name]", withString: name).stringByReplacing(string: "[url]", withString: link)
		
		email.to.append(Recipient(name: emailAddress, address: emailAddress))
		
		try email.send(/*completion: { (code, header, body) in
			responseCode = code
			print("email completion", code, header, body)
		}*/)
			
	}

	class func sendForgottenPasswordEmail(emailAddress: String, token: String, name: String) throws {
		
		let email = EMail(client: emailConfig.smtpClient)
		email.subject = "Recover password"
		email.from = Recipient(name: emailConfig.fromName, address: emailConfig.fromEmail)
		
		let link = "\(emailConfig.resetPasswordBaseUrl)?token=\(token)"
		
		email.html = emailConfig.resetPasswordEmailTemplate.stringByReplacing(string: "[name]", withString: name).stringByReplacing(string: "[url]", withString: link)

		email.to.append(Recipient(name: emailAddress, address: emailAddress))
		
		try email.send(/*completion: { (code, header, body) in
			print(code)
			print(header)
			print(body)
		}*/)
	}
}
