import Foundation
import PerfectHTTP
import PerfectMySQL

func resetPasswordRequest(request: HTTPRequest, response: HTTPResponse) {
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
			let (userId, name) = try storage.selectUser(byEmail: email)
			let (token, expiration) = Tokens.generateResetPasswordToken()
			try storage.insertResetPasswordToken(
				token: token,
				expiration: expiration,
				userId: userId
			)
			
			try EmailManager.sendForgottenPasswordEmail(
				emailAddress: email,
				token: token,
				name: name
			)
			try storage.commit()
			response.status = .ok

		} catch (let error) {
			try storage.rollback()
			throw error
		}
	} catch Err.request {
		response.status = .badRequest
	} catch Err.notFound {
		response.status = .notFound
	} catch {
		response.status = .internalServerError
	}
	
	response.completed()
}


func resetPassword(request: HTTPRequest, response: HTTPResponse) {
	response.setHeader(.contentType, value: "application/json")
	do {
		guard
			let bytes = request.postBodyBytes,
			let json = try JSONSerialization.jsonObject(
				with: Data(bytes: bytes),
				options: []
				) as? [String: Any],
			let token = json["token"] as? String,
			let password = json["password"] as? String
		else {
			throw Err.request
		}
		
		let storage = try PlusAuth.shared.storage()
		try storage.startTransaction()
		do {
			let (expiration, userId) = try storage.selectResetPasswordToken(token: token)
			let now = Int(Date().timeIntervalSince1970)
			guard now < expiration else {
				try storage.deleteResetPasswordToken(token: token)
				throw Err.expired
			}
			let hash = try Tokens.generatePasswordHash(password: password)
			try storage.updateUserHash(userId: userId, hash: hash)
			try storage.commit()
			response.status = .ok
		} catch (let error) {
			try storage.rollback()
			throw error
		}
	} catch Err.request {
		response.status = .badRequest
	} catch Err.notFound {
		response.status = .notFound
	} catch {
		response.status = .internalServerError
	}
	
	response.completed()
}
