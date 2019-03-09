import Foundation
import PerfectHTTP
import PerfectMySQL
import PerfectSMTP

// TODO: missing, verify accaount, resend verification email

public class PlusAuth {
	public static var shared: PlusAuth!
	
	let tokenConfig: TokenConfig
	let storageConfig: StorageConfig
	let emailConfig: EmailConfig

	public static func initializeSharedInstance(
		tokenConfig: TokenConfig,
		storageConfig: StorageConfig,
		emailConfig: EmailConfig
	) {
		shared = PlusAuth(
			tokenConfig: tokenConfig,
			storageConfig: storageConfig,
			emailConfig: emailConfig
		)
	}
	
	public init(
		tokenConfig: TokenConfig,
		storageConfig: StorageConfig,
		emailConfig: EmailConfig
	) {
		self.tokenConfig = tokenConfig
		self.storageConfig = storageConfig
		self.emailConfig = emailConfig
	}
	
	public func addRoutes(routes: inout Routes, uriPrefix: String?) {
		let prefix: String = uriPrefix ?? ""
		routes.add(method: .post, uri: "\(prefix)signin", handler: signIn)
		routes.add(method: .post, uri: "\(prefix)signup", handler: signUp)
		routes.add(method: .patch, uri: "\(prefix)verifyAccount", handler: verifyAccount)
		routes.add(method: .patch, uri: "\(prefix)resendVerificationEmail", handler: resendVerificationEmail)
		routes.add(method: .patch, uri: "\(prefix)refreshAccessToken", handler: refreshAccessToken)
		routes.add(method: .post, uri: "\(prefix)resetPassword", handler: resetPasswordRequest)
		routes.add(method: .patch, uri: "\(prefix)resetPassword", handler: resetPassword)
	}
	
	func storage() throws -> Storage {
		return try MySQLStorage(mysql: MySQL.new())
	}

}

public struct EmailConfig {
	public let smtpClient: SMTPClient
	public let fromName: String
	public let fromEmail: String
	public let verifyAccountBaseUrl: String
	public let resetPasswordBaseUrl: String
	
	public init(
		smtpClient: SMTPClient,
		fromName: String,
		fromEmail: String,
		verifyAccountBaseUrl: String,
		resetPasswordBaseUrl: String
	) {
		self.smtpClient = smtpClient
		self.fromName = fromName
		self.fromEmail = fromEmail
		self.verifyAccountBaseUrl = verifyAccountBaseUrl
		self.resetPasswordBaseUrl = resetPasswordBaseUrl
	}
}
