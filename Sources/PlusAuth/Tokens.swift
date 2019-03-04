import Foundation
import PerfectCrypto
import Scrypt

public typealias JWTPayload = [String: Any]

public struct TokenConfig {
	public let verifyAccountTokenExpiration: Int
	public let resetPasswordTokenExpiration: Int
	public let refreshTokenExpiration: Int
	public let scryptConfig: ScryptConfig
	public let jwtStaticConfig: JWTStaticConfig
	public let staticPayload: JWTPayload
	public let secretKey: Key
	
	
	public init(
		scryptConfig: ScryptConfig,
		jwtStaticConfig: JWTStaticConfig,
		refreshTokenExpiration: Int,
		resetPasswordTokenExpiration: Int,
		verifyAccountTokenExpiration: Int
		) {
		self.resetPasswordTokenExpiration = resetPasswordTokenExpiration
		self.scryptConfig = scryptConfig
		self.jwtStaticConfig = jwtStaticConfig
		self.staticPayload = Tokens.getStaticClaims(jwtStaticConfig: jwtStaticConfig)
		self.secretKey = HMACKey([UInt8](jwtStaticConfig.secretKey))
		self.refreshTokenExpiration = refreshTokenExpiration
		self.verifyAccountTokenExpiration = verifyAccountTokenExpiration
	}
}

var tokenConfig: TokenConfig {
	return PlusAuth.shared.tokenConfig
}

class Tokens {
	static func generateAccessToken(
		userId: String,
		hash: String,
		password: String,
		extraPayload: JWTPayload?
	) throws -> String {
		let isValidPassword = try Scrypt.check(mcf: hash, password: password)
		if (!isValidPassword) {
			throw Err.invalidPassword
		}
		let now = Date()
		var payload = tokenConfig.staticPayload
		payload["exp"] = Int(now.timeIntervalSince1970) + tokenConfig.jwtStaticConfig.expirationInterval
		payload["sub"] = userId

		if let extraPayload = extraPayload {
			payload.merge(extraPayload) { (_, new) in new }
		}
		
		guard let creator = JWTCreator(payload: payload) else {
			throw Err.invalid
		}
		
		let jwtAccessTokenStr = try creator.sign(
			alg: tokenConfig.jwtStaticConfig.algorithm,
			key: tokenConfig.secretKey,
			headers: tokenConfig.jwtStaticConfig.headers
		)
		return jwtAccessTokenStr
	}
	
	static func generateRefreshToken() -> (token: String, expiration: Int) {
		let now = Date()
		return (
			UUID().data.base64EncodedString(),
			Int(now.timeIntervalSince1970) + tokenConfig.refreshTokenExpiration
		)
	}
	
	static func refreshAccessToken(oldAccessToken: String) throws -> String {
		guard let verifier = JWTVerifier(oldAccessToken) else {
			throw Err.invalid
		}
		var payload = verifier.payload
		
		let now = Int(Date().timeIntervalSince1970)
		payload["exp"] = now + tokenConfig.jwtStaticConfig.expirationInterval
		
		guard let creator = JWTCreator(payload: payload) else {
			throw Err.unexpected
		}
		
		let newAccessToken = try creator.sign(
			alg: tokenConfig.jwtStaticConfig.algorithm,
			key: tokenConfig.secretKey
		)
		
		return newAccessToken
	}


	static func generateUserId() -> String {
		return UUID().data.base64EncodedString()
	}

	static func generatePasswordHash(password: String) throws -> String {
		let scryptConfig = tokenConfig.scryptConfig
		let salt = try Scrypt.generateSalt(length: scryptConfig.saltLength)
		let hash = try Scrypt.generateHash(
			password: password,
			salt: salt,
			N: scryptConfig.N,
			r: scryptConfig.r,
			p: scryptConfig.p,
			length: scryptConfig.hashLength
		)
		
		return "\(hash.base64EncodedString()).\(salt.base64EncodedString())"
	}
	
	static func generateVerifyAccountToken() -> (token: String, expiration: Int) {
		return (
			UUID().data.base64EncodedString(),
			Int(Date().timeIntervalSince1970) + tokenConfig.verifyAccountTokenExpiration
		)
	}
	
	static func generateResetPasswordToken() -> (token: String, expiration: Int) {
		return (
			token: UUID().data.base64EncodedString(),
			expiration: Int(Date().timeIntervalSince1970) + tokenConfig.resetPasswordTokenExpiration
		)
	}
	
	static func getAccessToken(bearer: String?) throws -> String {
		guard let bearerStr = bearer else {
			throw Err.invalid
		}
		let arr = bearerStr.split(separator: " ")
		guard
			arr.count == 2 &&
			arr[0] == "Bearer"
		else {
			throw Err.invalid
		}
		return String(arr[1])
	}

	static func getAccessTokenPayload(bearer: String?) throws -> [String: Any] {
		return try getAccessTokenPayload(
			accessToken: try getAccessToken(bearer: bearer)
		)
	}
	
	static func getAccessTokenPayload(accessToken: String) throws -> [String: Any] {
		guard let verifier = JWTVerifier.init(accessToken) else {
			throw Err.invalid
		}
		return verifier.payload
	}

	static func verifyBearer(_ header: String?) throws {
		try verifyAccessToken(getAccessToken(bearer: header))
	}
	
	static func verifyAccessToken(_ token: String) throws {
		guard let verifier = JWTVerifier.init(token) else {
			throw Err.invalid
		}
		try verifier.verify(algo: tokenConfig.jwtStaticConfig.algorithm, key: tokenConfig.secretKey)
		let exp = verifier.payload["exp"] as! Int
		let now = Int(Date().timeIntervalSince1970)
		if now > exp {
			throw Err.expired
		}
	}
	
	static func getStaticClaims(jwtStaticConfig: JWTStaticConfig) -> JWTPayload {
		var payload: JWTPayload = [:]
		if let iss = jwtStaticConfig.iss {
			payload["iss"] = iss
		}
		if let aud = jwtStaticConfig.aud {
			payload["aud"] = aud
		}
		if let publicClaims = jwtStaticConfig.publicClaims {
			payload.merge(publicClaims) { (_, new) in new }
		}
		if let privateClaims = jwtStaticConfig.privateClaims {
			payload.merge(privateClaims) { (_, new) in new }
		}
		return payload
	}
	
}

public struct ScryptConfig {
	public let hashLength: Int
	public let saltLength: Int
	public let N: Int
	public let r: Int
	public let p: Int
}

public struct JWTStaticConfig {
	public let algorithm: JWT.Alg
	public let secretKey: Data
	public let headers: JWTPayload
	public let expirationInterval: Int
	public let iss: String?
	public let aud: String?
	public let publicClaims: JWTPayload?
	public let privateClaims: JWTPayload?
}

