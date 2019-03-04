import Foundation
import PerfectHTTP
import PerfectMySQL

func refreshAccessToken(request: HTTPRequest, response: HTTPResponse) {
	response.setHeader(.contentType, value: "application/json")
	do {
		guard
			let bytes = request.postBodyBytes,
			let json = try JSONSerialization.jsonObject(
				with: Data(bytes: bytes),
				options: []
				) as? [String: Any],
			let refreshToken = json["refreshToken"] as? String
		else {
			throw Err.request
		}
		
		let storage = try PlusAuth.shared.storage()
		
		let accessToken = try Tokens.getAccessToken(bearer: request.header(.authorization))
		
		let (expiration, userId) = try storage.selectRefreshToken(token: refreshToken)
		
		let verified = try storage.selectUserVerified(byId: userId)
		
		guard verified else {
			throw Err.unverified
		}
		
		let now = Int(Date().timeIntervalSince1970)
		
		guard now < expiration else {
			try storage.deleteRefreshToken(token: refreshToken)
			throw Err.expired
		}
		
		let oldPayload = try Tokens.getAccessTokenPayload(accessToken: accessToken)
		
		guard
			let sub = oldPayload["sub"] as? String,
			sub == userId
		else {
			throw Err.invalid
		}
		
		let newAccessToken = try Tokens.refreshAccessToken(oldAccessToken: accessToken)
		
		// TODO: do we need to regenerate new refresh token? Explore best practices
		
		let body = [
			"accessToken": newAccessToken
		]
		
		response.setBody(bytes: body.toBytes())
		response.status = .ok

	} catch Err.unverified {
		response.status = .methodNotAllowed
	} catch Err.request {
		response.status = .badRequest
	} catch Err.notFound {
		response.status = .notFound
	} catch {
		response.status = .internalServerError
	}
	
	response.completed()
}
