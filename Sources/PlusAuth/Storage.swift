import Foundation
import PerfectMySQL

public enum StorageConfig {
	case mysql(MySQLConfig)
	// below not implemented, if we need to migrate for any reason
	case postgress
	case mongodb
	case orm
}

protocol Storage {
	// Users / Sccounts
	func startTransaction() throws
	func commit() throws
	func rollback() throws
	
	func selectUser(byEmail email: String) throws -> (id: String, name: String)
	func selectUserHash(byEmail email: String) throws -> (id: String, hash: String)
	func selectUserVerified(byEmail email: String) throws -> (id: String, verified: Bool, name: String)
	func selectUserVerified(byId id: String) throws -> Bool
	func insertUser(userId: String, email: String, hash: String, name: String) throws
	func updateUserHash(userId: String, hash: String) throws
	func updateUserVerification(userId: String, verified: Bool) throws
	func selectUserName(id: String) throws -> String

	// Refresh Tokens
	func insertRefreshToken(userId: String, token: String, expiration: Int64, appId: String) throws
	func selectRefreshToken(token: String) throws -> (expiration: Int64, userId: String, appId: String)
	func deleteRefreshToken(token: String) throws

	// Verify Account Tokens
	func insertVerifyAccountToken(token: String, expiration: Int64, userId: String) throws
	func selectVerifyAccountToken(token: String) throws -> (expiration: Int64, userId: String)
	func deleteVerifyAccountToken(token: String) throws

	// Reset Password Tokens
	func insertResetPasswordToken(token: String, expiration: Int64, userId: String) throws
	func selectResetPasswordToken(token: String) throws -> (expiration: Int64, userId: String)
	func deleteResetPasswordToken(token: String) throws
}
