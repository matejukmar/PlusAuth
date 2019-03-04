import Foundation
import PerfectMySQL

protocol Storage {
	// Users / Sccounts
	func selectUserId(byEmail email: String) throws -> String
	func selectUserHash(byEmail email: String) throws -> (id: String, hash: String)
	func selectUserVerified(byEmail email: String) throws -> (id: String, verified: Bool)
	func selectUserVerified(byId id: String) throws -> Bool
	func insertUser(userId: String, email: String, hash: String) throws
	func updateUserHash(userId: String, hash: String) throws
	func updateUserVerification(userId: String, verified: Bool) throws

	// Refresh Tokens
	func insertRefreshToken(userId: String, token: String, expiration: Int) throws
	func selectRefreshToken(token: String) throws -> (expiration: Int, userId: String)
	func deleteRefreshToken(token: String) throws

	// Verify Account Tokens
	func insertVerifyAccountToken(token: String, expiration: Int, userId: String) throws
	func selectVerifyAccountToken(token: String) throws -> (expiration: Int, userId: String)
	func deleteVerifyAccountToken(token: String) throws

	// Reset Password Tokens
	func insertResetPasswordToken(token: String, expiration: Int, userId: String) throws
	func selectResetPasswordToken(token: String) throws -> (expiration: Int, userId: String)
	func deleteResetPasswordToken(token: String) throws
}
