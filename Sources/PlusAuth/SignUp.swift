import Foundation
import PerfectHTTP
import PerfectMySQL

func signUp(request: HTTPRequest, response: HTTPResponse) {
	response.setHeader(.contentType, value: "application/json")
	do {
		guard
			let bytes = request.postBodyBytes,
			let json = try JSONSerialization.jsonObject(
				with: Data(bytes: bytes),
				options: []
				) as? [String: Any],
			let email = json["email"] as? String,
			let password = json["password"] as? String
		else {
			throw Err.request
		}
		
		let storage = try PlusAuth.shared.storage()

		let userId = Tokens.generateUserId()
		let hash = try Tokens.generatePasswordHash(password: password)
		
		try storage.insertUser(userId: userId, email: email, hash: hash)
		
		let (token, expiration) = Tokens.generateVerifyAccountToken()
		
		try storage.insertVerifyAccountToken(
			token: token,
			expiration: expiration,
			userId: userId
		)
		
		try EmailManager.sendVerifyAccountEmail(emailAddress: email, token: token)

		response.status = .ok
	} catch {
		response.status = .internalServerError
	}
	response.completed()
}

func verifyAccount(request: HTTPRequest, response: HTTPResponse) {
	response.setHeader(.contentType, value: "application/json")
	do {
		guard
			let bytes = request.postBodyBytes,
			let json = try JSONSerialization.jsonObject(
				with: Data(bytes: bytes),
				options: []
				) as? [String: Any],
			let token = json["token"] as? String
			else {
				throw Err.request
		}
		
		let storage = try PlusAuth.shared.storage()
		
		let (expiration, userId) = try storage.selectVerifyAccountToken(token: token)
		
		let now = Int(Date().timeIntervalSince1970)
		
		guard now < expiration else {
			try storage.deleteVerifyAccountToken(token: token)
			throw Err.expired
		}
		
		try storage.updateUserVerification(userId: userId, verified: true)
		
		response.status = .ok
	} catch {
		response.status = .internalServerError
	}
	response.completed()
}

func resendVerificationEmail(request: HTTPRequest, response: HTTPResponse) {
	response.setHeader(.contentType, value: "application/json")
	do {
		guard
			let bytes = request.postBodyBytes,
			let json = try JSONSerialization.jsonObject(
				with: Data(bytes: bytes),
				options: []
				) as? [String: Any],
			let email = json["email"] as? String
			else {
				throw Err.request
		}
		
		let storage = try PlusAuth.shared.storage()
		
		let (userId, verified) = try storage.selectUserVerified(byEmail: email)
		
		guard !verified else {
			throw Err.invalid
		}
		
		let (token, expiration) = Tokens.generateVerifyAccountToken()
		
		try storage.insertVerifyAccountToken(
			token: token,
			expiration: expiration,
			userId: userId
		)
		
		try EmailManager.sendVerifyAccountEmail(emailAddress: email, token: token)

		response.status = .ok
	} catch {
		response.status = .internalServerError
	}
	response.completed()
}