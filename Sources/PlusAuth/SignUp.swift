import Foundation
import PerfectHTTP
import PerfectMySQL
import PerfectSMTP

func signUp(request: HTTPRequest, response: HTTPResponse) {
	response.setHeader(.contentType, value: "application/json")
	do {
		guard
			let bytes = request.postBodyBytes,
			let json = try JSONSerialization.jsonObject(
				with: Data(bytes: bytes),
				options: []
				) as? [String: Any],
			let name = json["name"] as? String,
			let email = json["email"] as? String,
			let password = json["password"] as? String
		else {
			throw Err.request
		}
		
		let storage = try PlusAuth.shared.storage()
		try storage.startTransaction()
		do {
			let userId = Tokens.generateUserId()
			let hash = try Tokens.generatePasswordHash(password: password)
			
			try storage.insertUser(userId: userId, email: email, hash: hash, name: name)
			
			let (token, expiration) = Tokens.generateVerifyAccountToken()
			
			try storage.insertVerifyAccountToken(
				token: token,
				expiration: expiration,
				userId: userId
			)
			try EmailManager.sendVerifyAccountEmail(emailAddress: email, token: token, name: name)
			try storage.commit()
			response.status = .ok
		} catch (let error) {
			try storage.rollback()
			throw error
		}
	} catch Err.request {
		response.status = .badRequest
	} catch	SMTPError.general(let code, let message) {
		print("smtp code", code, "error", message)
		response.status = .internalServerError
	} catch Err.alreadyExists {
		response.status = .conflict
	} catch (let error){
		print("other err", error)
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
		try storage.startTransaction()
		do {
			let (expiration, userId) = try storage.selectVerifyAccountToken(token: token)
			let now = Int64(Date().timeIntervalSince1970)
			guard now < expiration else {
				try storage.deleteVerifyAccountToken(token: token)
				throw Err.expired
			}
			try storage.updateUserVerification(userId: userId, verified: true)
			try storage.deleteVerifyAccountToken(token: token)
			try storage.commit()
			response.status = .ok
		} catch (let error) {
			try storage.rollback()
			throw error
		}
	} catch Err.notFound {
		response.status = .notFound
	} catch Err.expired {
		response.status = .unauthorized
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
		try storage.startTransaction()
		do {
			let (userId, verified, name) = try storage.selectUserVerified(byEmail: email)
			guard !verified else {
				throw Err.invalid
			}
			let (token, expiration) = Tokens.generateVerifyAccountToken()
			try storage.insertVerifyAccountToken(
				token: token,
				expiration: expiration,
				userId: userId
			)
			try EmailManager.sendVerifyAccountEmail(emailAddress: email, token: token, name: name)
			try storage.commit()
			response.status = .ok
		} catch (let error) {
			try storage.rollback()
			throw error
		}
	} catch Err.invalid {
		response.status = .badRequest
	} catch {
		response.status = .internalServerError
	}
	response.completed()
}
