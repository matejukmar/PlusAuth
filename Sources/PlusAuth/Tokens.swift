import Foundation
import PerfectCrypto
import Scrypt

public typealias JWTPayload = [String: Any]

public struct TokenConfig {
	public let verifyAccountTokenExpiration: Int64
	public let resetPasswordTokenExpiration: Int64
	public let refreshTokenExpiration: Int64
	public let scryptConfig: ScryptConfig
	public let jwtStaticConfig: JWTStaticConfig
	public let staticPayload: JWTPayload
	
	
	public init(
		scryptConfig: ScryptConfig,
		jwtStaticConfig: JWTStaticConfig,
		refreshTokenExpiration: Int64,
		resetPasswordTokenExpiration: Int64,
		verifyAccountTokenExpiration: Int64
	) {
		self.resetPasswordTokenExpiration = resetPasswordTokenExpiration
		self.scryptConfig = scryptConfig
		self.jwtStaticConfig = jwtStaticConfig
		self.staticPayload = Tokens.getStaticClaims(jwtStaticConfig: jwtStaticConfig)
		self.refreshTokenExpiration = refreshTokenExpiration
		self.verifyAccountTokenExpiration = verifyAccountTokenExpiration
	}
}

var tokenConfig: TokenConfig {
	return PlusAuth.shared.tokenConfig
}

public class Tokens {
	
	public static func generateAccessToken(
		userId: String,
		extraPayload: JWTPayload?
	) throws -> String {
		let conf = tokenConfig.jwtStaticConfig
		let now = Date()
		var payload = tokenConfig.staticPayload
		payload["exp"] = String(Int64(now.timeIntervalSince1970) + conf.expirationInterval)
		payload["sub"] = userId

		if let extraPayload = extraPayload {
			payload.merge(extraPayload) { (_, new) in new }
		}
		
		guard let creator = JWTCreator(payload: payload) else {
			throw Err.invalid
		}
		
		let jwtAccessTokenStr = try creator.sign(
			alg: conf.algorithm,
			key: conf.secretKey,
			headers: conf.headers ?? [:]
		)
		return jwtAccessTokenStr
	}
	
	public static func generateRefreshToken() -> (token: String, expiration: Int64) {
		let now = Date()
		return (
			UUID().data.base64EncodedString(),
			Int64(now.timeIntervalSince1970) + tokenConfig.refreshTokenExpiration
		)
	}
	
	public static func refreshAccessToken(oldAccessToken: String) throws -> String {
		guard let verifier = JWTVerifier(oldAccessToken) else {
			throw Err.invalid
		}
		
		let conf = tokenConfig.jwtStaticConfig
		try verifier.verify(algo: conf.algorithm, key: conf.secretKey)

		var payload = verifier.payload
		
		let now = Int64(Date().timeIntervalSince1970)
		payload["exp"] = String(now + conf.expirationInterval)
		
		guard let creator = JWTCreator(payload: payload) else {
			throw Err.unexpected
		}
		
		let newAccessToken = try creator.sign(
			alg: conf.algorithm,
			key: conf.secretKey,
			headers: conf.headers ?? [:]
		)
		
		return newAccessToken
	}


	public static func generateUserId() -> String {
		return UUID().data.base64EncodedString()
	}

	public static func generatePasswordHash(password: String) throws -> String {
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
	
	public static func verifyPasswordHash(hash: String, password: String) throws {
		guard let passwordData = password.data(using: .utf8) else {
			throw Err.invalid
		}
		
		let arr = hash.split(separator: ".")
		
		guard arr.count == 2 else {
			throw Err.invalid
		}
		
		guard let hashData = Data(base64Encoded: String(arr[0])) else {
			throw Err.invalid
		}

		guard let saltData = Data(base64Encoded: String(arr[1])) else {
			throw Err.invalid
		}

		let conf = tokenConfig.scryptConfig

		try Scrypt.matchPassword(
			password: passwordData,
			salt: saltData,
			hash: hashData,
			N: conf.N,
			r: conf.r,
			p: conf.p,
			length: conf.hashLength
		)
	}
	
	public static func generateVerifyAccountToken() -> (token: String, expiration: Int64) {
		return (
			UUID().data.base64EncodedString(),
			Int64(Date().timeIntervalSince1970) + tokenConfig.verifyAccountTokenExpiration
		)
	}
	
	public static func generateResetPasswordToken() -> (token: String, expiration: Int64) {
		return (
			token: UUID().data.base64EncodedString(),
			expiration: Int64(Date().timeIntervalSince1970) + tokenConfig.resetPasswordTokenExpiration
		)
	}
	
	public static func getAccessToken(bearer: String?) throws -> String {
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

	public static func getAccessTokenPayload(bearer: String?) throws -> [String: Any] {
		return try getAccessTokenPayload(
			accessToken: try getAccessToken(bearer: bearer)
		)
	}
	
	public static func getAccessTokenPayload(accessToken: String) throws -> [String: Any] {
		guard let verifier = JWTVerifier.init(accessToken) else {
			throw Err.invalid
		}
		return verifier.payload
	}

	public static func verifyBearer(_ header: String?) throws {
		try verifyAccessToken(getAccessToken(bearer: header))
	}
	
	public static func verifyAccessToken(_ token: String) throws {
		guard let verifier = JWTVerifier.init(token) else {
			throw Err.invalid
		}
		let conf = tokenConfig.jwtStaticConfig
		try verifier.verify(algo: conf.algorithm, key: conf.secretKey)
		guard let expStr = verifier.payload["exp"] as? String else {
			throw Err.invalid
		}
		guard let exp = Int64(expStr) else {
			throw Err.invalid
		}
		let now = Int64(Date().timeIntervalSince1970)
		if now > exp {
			throw Err.expired
		}
	}
	
	public static func getStaticClaims(jwtStaticConfig: JWTStaticConfig) -> JWTPayload {
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

	public init(
		hashLength: Int,
		saltLength: Int,
		N: Int,
		r: Int,
		p: Int
	) {
		self.hashLength = hashLength
		self.saltLength = saltLength
		self.N = N
		self.r = r
		self.p = p
	}
}

public struct JWTStaticConfig {
	public let algorithm: JWT.Alg
	public let secretKey: Key
	public let headers: JWTPayload?
	public let expirationInterval: Int64
	public let iss: String?
	public let aud: String?
	public let publicClaims: JWTPayload?
	public let privateClaims: JWTPayload?
	
	public init(
		algorithm: JWT.Alg,
		secretKey: Key,
		headers: JWTPayload?,
		expirationInterval: Int64,
		iss: String?,
		aud: String?,
		publicClaims: JWTPayload?,
		privateClaims: JWTPayload?
	) {
		self.algorithm = algorithm
		self.secretKey = secretKey
		self.headers = headers
		self.expirationInterval = expirationInterval
		self.iss = iss
		self.aud = aud
		self.publicClaims = publicClaims
		self.privateClaims = privateClaims
	}
}

