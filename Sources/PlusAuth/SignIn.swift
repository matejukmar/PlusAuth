import Foundation
import PerfectHTTP
import PerfectMySQL
import Scrypt

func signIn(request: HTTPRequest, response: HTTPResponse) {
	response.setHeader(.contentType, value: "application/json")
	do {
		let bytes1 = request.postBodyBytes!
		let str = String(bytes: bytes1, encoding: .utf8)!
		print("json", str);
		guard
			let bytes = request.postBodyBytes,
			let json = try JSONSerialization.jsonObject(
				with: Data(bytes: bytes),
				options: []
				) as? [String: Any],
			let email = json["email"] as? String,
			let password = json["password"] as? String,
			let appId = json["appId"] as? String,
			let rememberLogin = json["rememberLogin"] as? Bool
			else {
				throw Err.request
		}
		
		let storage = try PlusAuth.shared.storage()
		try storage.startTransaction()
		do {
			let (userId, hash) = try storage.selectUserHash(byEmail: email)
			
			try Tokens.verifyPasswordHash(hash: hash, password: password)
			
			let accessToken = try Tokens.generateAccessToken(
				userId: userId,
				extraPayload: nil
			)
			var body: [String: Any] = ["accessToken": accessToken]
			if (rememberLogin) {
				let (refreshToken, expiration) = Tokens.generateRefreshToken()
				try storage.insertRefreshToken(userId: userId, token: refreshToken, expiration: expiration, appId: appId)
				body["refreshToken"] = [
					"token": refreshToken,
					"expiration": expiration
				]
			}
			try storage.commit()
			response.setBody(bytes: body.toBytes())
			response.status = .ok
		} catch (let error) {
			try storage.rollback()
			throw error
		}
	} catch Err.request {
		response.status = .badRequest
	} catch Scrypt.Err.invalidPassword {
		response.status = .unauthorized
	} catch Err.notFound {
		response.status = .notFound
	} catch (let error) {
		print("error", error)
		response.status = .internalServerError
	}
	
	response.completed()
}
