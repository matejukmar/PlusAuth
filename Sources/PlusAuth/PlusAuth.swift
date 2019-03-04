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
		routes.add(method: .post, uri: "\(prefix)resetPasswordRequest", handler: resetPasswordRequest)
		routes.add(method: .post, uri: "\(prefix)resetPassword", handler: resetPassword)
	}
	
	func storage() throws -> Storage {
		return try MySQLStorage(mysql: MySQL.new())
	}

}

public enum StorageConfig {
	case mysql(MySQLConfig)
	// below not implemented, if we need to migrate for any reason
	case postgress
	case mongodb
	case orm
}

public struct EmailConfig {
	public let smtpClient: SMTPClient
	public let fromName: String
	public let fromEmail: String
	public let verifyAccountBaseUrl: String
	public let resetPasswordBaseUrl: String
}
