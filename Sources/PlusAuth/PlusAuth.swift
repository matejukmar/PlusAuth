import Foundation
import PerfectCrypto
import Scrypt

public typealias JWTPayload = [String: Any]

public class PlusAuth {
  let mySQLConfig: MySQLConfig
  let resetPasswordConfig: ResetPasswordConfig
  let passwordScryptConfig: PasswordScryptConfig
  let jwtStaticConfig: JWTStaticConfig
  let refreshTokenConfig: RefreshTokenConfig
  let staticPayload: JWTPayload
  let secretKey: Key
  
  public init(
    mySQLConfig: MySQLConfig,
    resetPasswordConfig: ResetPasswordConfig,
    passwordScryptConfig: PasswordScryptConfig,
    jwtStaticConfig: JWTStaticConfig,
    refreshTokenConfig: RefreshTokenConfig
  ) {
    self.mySQLConfig = mySQLConfig
    self.resetPasswordConfig = resetPasswordConfig
    self.passwordScryptConfig = passwordScryptConfig
    self.jwtStaticConfig = jwtStaticConfig
    self.staticPayload = PlusAuth.getStaticClaims(jwtStaticConfig: jwtStaticConfig)
    self.secretKey = HMACKey([UInt8](jwtStaticConfig.secretKey))
    self.refreshTokenConfig = refreshTokenConfig
  }
  
  public func signIn(username: String, password: String, addToPayload: ((Account) -> JWTPayload)?) throws -> SignInResult {
    let account = Account(auth: self)
    try account.find([("username", username)])
    let isValidPassword = try Scrypt.check(mcf: account.hash, password: password)
    if (!isValidPassword) {
      throw PlusError.invalidPassword
    }
    let now = Date()
    var payload = staticPayload
    payload["exp"] = Int(now.timeIntervalSince1970) + jwtStaticConfig.expirationInterval
    payload["sub"] = account.id
    if let addToPayload2 = addToPayload {
      let dynamicPayload = addToPayload2(account)
      payload.merge(dynamicPayload) { (_, new) in new }
    }

    guard let creator = JWTCreator(payload: payload) else {
      throw PlusError.invalidData
    }

    let jwtAccessTokenStr = try creator.sign(
      alg: jwtStaticConfig.algorithm,
      key: secretKey,
      headers: jwtStaticConfig.headers
    )
    
    let refreshToken = RefreshToken(auth: self)
    refreshToken.value = UUID().data.base64EncodedString()
    refreshToken.accountId = account.id
    refreshToken.expiration =  Int(now.timeIntervalSince1970) + refreshTokenConfig.expirationInterval
    try refreshToken.create()
    
    return SignInResult(
      account: account,
      accessToken: jwtAccessTokenStr,
      refreshToken: refreshToken
    )
  }
  
  public func signUp(username: String, password: String) throws -> Account {
    let salt = try Scrypt.generateSalt(length: passwordScryptConfig.saltLength)
    let hash = try Scrypt.generateHash(
      password: password,
      salt: salt,
      N: passwordScryptConfig.N,
      r: passwordScryptConfig.r,
      p: passwordScryptConfig.p,
      length: passwordScryptConfig.hashLength
    )
    let account = Account(auth: self)
    account.id = UUID().data.base64EncodedString()
    account.username = username
    account.hash = "\(hash.base64EncodedString()).\(salt.base64EncodedString())"
    try account.create()
    return account
  }
  
  public func verify(accessToken: String) throws -> Bool {
    guard let verifier = JWTVerifier.init(accessToken) else {
      throw PlusError.unexpectedError
    }
    do {
      try verifier.verify(algo: jwtStaticConfig.algorithm, key: secretKey)
      let exp = verifier.payload["exp"] as! Int
      let now = Int(Date().timeIntervalSince1970)
      if now > exp {
        throw PlusError.expired
      }
      return true
    } catch {
      return false
    }
  }
  
  public func refreshAccessToken(accessToken: String, refreshToken: String, modifyPayload: ((JWTPayload) -> JWTPayload)?) throws -> String {
    let token = RefreshToken(auth: self)
    try token.get(refreshToken)
    let now = Int(Date().timeIntervalSince1970)
    if now > token.expiration {
      throw PlusError.expired
    }
    guard let verifier = JWTVerifier(accessToken) else {
      throw PlusError.unexpectedError
    }
    var payload = verifier.payload
    if let modPayl = modifyPayload {
        payload = modPayl(payload)
    }
    guard let creator = JWTCreator(payload: payload) else {
      throw PlusError.unexpectedError
    }
    let newAccessToken = try creator.sign(alg: jwtStaticConfig.algorithm, key: secretKey)
    return newAccessToken
  }
  
  public func generateResetPasswordToken(username: String) throws -> String {
    let account = Account(auth: self)
    try account.find([("username", username)])
    let token = ResetPasswordToken(auth: self)
    token.value = UUID().data.base64EncodedString()
    token.accountId = account.id
    token.expiration = Int(Date().timeIntervalSince1970) + resetPasswordConfig.expirationInterval
    try token.create()
    return token.value
  }
  
  public func resetPassword(token: String, newPassword: String) throws {
    let rpToken = ResetPasswordToken(auth: self)
    try rpToken.get(token)
    let account = Account(auth: self)
    try account.get(rpToken.accountId)
    let salt = try Scrypt.generateSalt(length: passwordScryptConfig.saltLength)
    let hash = try Scrypt.generateHash(
      password: newPassword,
      salt: salt,
      N: passwordScryptConfig.N,
      r: passwordScryptConfig.r,
      p: passwordScryptConfig.p,
      length: passwordScryptConfig.hashLength
    )
    account.hash = "\(hash.base64EncodedString()).\(salt.base64EncodedString())"
    try account.save()
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

public struct ResetPasswordConfig {
  let expirationInterval: Int
}

public struct MySQLConfig {
  let host: String
  let user: String
  let password: String
  let database: String
  let tablePrefix: String
}

public struct PasswordScryptConfig {
  let hashLength: Int
  let saltLength: Int
  let N: Int
  let r: Int
  let p: Int
}

public struct JWTStaticConfig {
  let algorithm: JWT.Alg
  let secretKey: Data
  let headers: JWTPayload
  let expirationInterval: Int
  let iss: String?
  let aud: String?
  let publicClaims: JWTPayload?
  let privateClaims: JWTPayload?
}

public struct RefreshTokenConfig {
  let expirationInterval: Int
}

public struct SignInResult {
  let account: Account
  let accessToken: String
  let refreshToken: RefreshToken
}

extension UUID {
  var bytes: [UInt8] {
    return Mirror(reflecting: uuid).children.map({$0.1 as! UInt8})
  }
  
  var data: Data {
    return Data(bytes: bytes)
  }
}
