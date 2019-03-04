import Foundation
import PerfectHTTP
import PerfectMySQL

func signIn(request: HTTPRequest, response: HTTPResponse) {
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
		
		let (userId, hash) = try storage.selectUserHash(byEmail: email)
		
		let accessToken = try Tokens.generateAccessToken(
			userId: userId,
			hash: hash,
			password: password,
			extraPayload: nil
		)
		
		let (refreshToken, expiration) = Tokens.generateRefreshToken()
		
		try storage.insertRefreshToken(userId: userId, token: refreshToken, expiration: expiration)
		
		let body: [String: Any] = [
			"accessToken": accessToken,
			"refreshToken": refreshToken,
			"refreshTokenExpiration": expiration
		]
		
		response.setBody(bytes: body.toBytes())
	} catch Err.request {
		response.status = .badRequest
	} catch Err.notFound {
		response.status = .notFound
	} catch {
		response.status = .internalServerError
	}
	
	response.completed()
}
