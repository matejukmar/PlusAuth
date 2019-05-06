import Foundation
import PerfectMySQL

public let MYSQL_DATE_FORMAT = "yyyy-MM-dd HH:mm:ss"

public struct MySQLConfig {
	public let host: String
	public let user: String
	public let password: String
	public let db: String
	
	public init(
		host: String,
		user: String,
		password: String,
		db: String
	) {
		self.host = host
		self.user = user
		self.password = password
		self.db = db
	}
}

public  extension Date {
	public var mySQLStr: String {
		let df = DateFormatter()
		df.dateFormat = MYSQL_DATE_FORMAT
		return df.string(from: self)
	}
	
	public init?(mySQLStr: String) {
		let df = DateFormatter()
		df.dateFormat = MYSQL_DATE_FORMAT
		if let date = df.date(from: mySQLStr) {
			self = date
		} else {
			return nil
		}
	}
}

public extension MySQL {
	public static func new() throws -> MySQL {
		let mysql = MySQL()
		
		switch PlusAuth.shared.storageConfig {
		case .mysql(let config):
			let status = mysql.connect(
				host: config.host,
				user: config.user,
				password: config.password
			)
			guard status else {
				throw Err.mysql
			}
			guard mysql.selectDatabase(named: config.db) else {
				throw Err.mysql
			}
			return mysql
		default:
			throw Err.mysql
		}
	}
}

class MySQLStorage: Storage {
	
	let mysql: MySQL
	init(mysql: MySQL) {
		self.mysql = mysql
	}
	
	func startTransaction() throws {
		guard mysql.query(statement: "START TRANSACTION") else {
			throw Err.mysql
		}
	}
	
	func commit() throws {
		guard mysql.query(statement: "COMMIT") else {
			throw Err.mysql
		}
	}
	
	func rollback() throws {
		guard mysql.query(statement: "ROLLBACK") else {
			throw Err.mysql
		}
	}
	
	func selectUser(byEmail email: String) throws -> (id: String, name: String) {
		let st = MySQLStmt(mysql)
		guard st.prepare(statement: "select id, name from Users where email = ? and deleted = ?") else {
			throw Err.mysql
		}
		st.bindParam(email)
		st.bindParam(0)
		
		guard st.execute() else {
			print(mysql.errorMessage())
			throw Err.mysql
		}
		
		let results = st.results()
		
		guard let row = results.next() else {
			throw Err.notFound
		}
		return (row[0] as! String, row[1] as! String)
	}
	
	func selectUserHash(byEmail email: String) throws -> (id: String, hash: String) {
		let st = MySQLStmt(mysql)
		guard st.prepare(statement: "select id, hash from Users where email = ? and deleted = ?") else {
			throw Err.mysql
		}
		st.bindParam(email)
		st.bindParam(0)
		
		guard st.execute() else {
			print(mysql.errorMessage())
			throw Err.mysql
		}
		
		let results = st.results()
		
		guard let row = results.next() else {
			throw Err.notFound
		}
		return (row[0] as! String, row[1] as! String)
	}
	
	func selectUserVerified(byEmail email: String) throws -> (id: String, verified: Bool, name: String) {
		let st = MySQLStmt(mysql)
		guard st.prepare(statement: "select id, verified, name from Users where email = ? and deleted = ?") else {
			throw Err.mysql
		}
		st.bindParam(email)
		st.bindParam(0)
		
		guard st.execute() else {
			print(mysql.errorMessage())
			throw Err.mysql
		}
		
		let results = st.results()
		
		guard let row = results.next() else {
			throw Err.notFound
		}
		return (row[0] as! String, (row[1] as! Int8) > 0, row[2] as! String)
	}
	
	func selectUserVerified(byId id: String) throws -> Bool {
		let st = MySQLStmt(mysql)
		guard st.prepare(statement: "select verified from Users where id = ? and deleted = ?") else {
			throw Err.mysql
		}
		st.bindParam(id)
		st.bindParam(0)
		
		guard st.execute() else {
			print(mysql.errorMessage())
			throw Err.mysql
		}
		
		let results = st.results()
		
		guard let row = results.next() else {
			throw Err.notFound
		}
		return (row[0] as! Int8) > 0
	}

	
	func insertUser(userId: String, email: String, hash: String, name: String) throws {
		let st = MySQLStmt(mysql)
		
		guard st.prepare(statement: "insert into Users (id, email, hash, name, verified, deleted) values (?, ?, ?, ?, ?, ?)") else {
			throw Err.mysql
		}
		st.bindParam(userId)
		st.bindParam(email)
		st.bindParam(hash)
		st.bindParam(name)
		st.bindParam(0)
		st.bindParam(0)
		
		guard st.execute() else {
			print("error", mysql.errorCode(), mysql.errorMessage())
			if (mysql.errorCode() == 1062) {
				throw Err.alreadyExists
			} else {
				throw Err.mysql
			}
		}
	}
	
	func updateUserHash(userId: String, hash: String) throws {
		let st = MySQLStmt(mysql)
		
		guard st.prepare(statement: "update Users set hash=? where id = ?") else {
			throw Err.mysql
		}
		
		st.bindParam(hash)
		st.bindParam(userId)
		
		guard st.execute() else {
			throw Err.mysql
		}
	}
	
	func updateUserVerification(userId: String, verified: Bool) throws {
		let st = MySQLStmt(mysql)
		
		guard st.prepare(statement: "update Users set verified = ? where id = ?") else {
			throw Err.mysql
		}
		
		st.bindParam(verified ? 1 : 0)
		st.bindParam(userId)
		
		guard st.execute() else {
			throw Err.mysql
		}
	}
	
	func selectUserName(id: String) throws -> String {
		let st = MySQLStmt(mysql)
		
		guard st.prepare(statement: "select name from Users where id = ?") else {
			throw Err.mysql
		}
		
		st.bindParam(id)
		
		guard st.execute() else {
			throw Err.mysql
		}
		
		let results = st.results()
		
		guard let row = results.next() else {
			throw Err.notFound
		}
		
		return row[0] as! String
	}


	
	func insertRefreshToken(userId: String, token: String, expiration: Int64, appId: String) throws {
		let st = MySQLStmt(mysql)
		guard st.prepare(statement: """
			insert into RefreshTokens
			(userId, token, expiration, appId)
			values
			(?, ?, ?, ?)
			on duplicate key update
			token = ?,
			expiration = ?
		""") else {
			throw Err.mysql
		}
		st.bindParam(userId)
		st.bindParam(token)
		st.bindParam(expiration)
		st.bindParam(appId)
		st.bindParam(token)
		st.bindParam(expiration)

		guard st.execute() else {
			throw Err.mysql
		}
	}
	
	func selectRefreshToken(token: String) throws -> (expiration: Int64, userId: String, appId: String) {
		let st = MySQLStmt(mysql)
		
		guard st.prepare(
			statement: "select expiration, userId, appId from RefreshTokens where token = ?"
			) else {
				throw Err.mysql
		}
		
		st.bindParam(token)
		
		guard st.execute() else {
			throw Err.mysql
		}
		
		let results = st.results()
		
		guard let row = results.next() else {
			throw Err.notFound
		}
		
		return (row[0] as! Int64, row[1] as! String, row[2] as! String)
	}
	
	func deleteRefreshToken(token: String) throws {
		let st = MySQLStmt(mysql)
		
		guard st.prepare(
			statement: "delete from RefreshTokens where token = ?"
			) else {
				throw Err.mysql
		}
		
		st.bindParam(token)
		
		guard st.execute() else {
			throw Err.mysql
		}
	}
	
	
	func insertVerifyAccountToken(token: String, expiration: Int64, userId: String) throws {
		let st = MySQLStmt(mysql)
		guard st.prepare(statement: "insert into VerifyAccountTokens (token, expiration, userId) values (?, ?, ?)") else {
			throw Err.mysql
		}
		
		st.bindParam(token)
		st.bindParam(expiration)
		st.bindParam(userId)
		
		guard st.execute() else {
			throw Err.mysql
		}
	}
	
	func selectVerifyAccountToken(token: String) throws -> (expiration: Int64, userId: String) {
		let st = MySQLStmt(mysql)
		
		guard st.prepare(
			statement: "select expiration, userId from VerifyAccountTokens where token = ?"
			) else {
				throw Err.mysql
		}
		
		st.bindParam(token)
		
		guard st.execute() else {
			throw Err.mysql
		}
		
		let results = st.results()
		
		guard let row = results.next() else {
			throw Err.notFound
		}
		
		return (row[0] as! Int64, row[1] as! String)
	}
	
	func deleteVerifyAccountToken(token: String) throws {
		let st = MySQLStmt(mysql)
		
		guard st.prepare(
			statement: "delete from VerifyAccountTokens where token = ?"
			) else {
				throw Err.mysql
		}
		
		st.bindParam(token)
		
		guard st.execute() else {
			throw Err.mysql
		}
	}
	
	func insertResetPasswordToken(token: String, expiration: Int64, userId: String) throws {
		let st = MySQLStmt(mysql)
		guard st.prepare(statement: "insert into ResetPasswordTokens (token, expiration, userId) values (?, ?, ?)") else {
			throw Err.mysql
		}
		
		st.bindParam(token)
		st.bindParam(expiration)
		st.bindParam(userId)
		
		guard st.execute() else {
			throw Err.mysql
		}
	}
	
	func selectResetPasswordToken(token: String) throws -> (expiration: Int64, userId: String) {
		let st = MySQLStmt(mysql)
		
		guard st.prepare(
			statement: "select expiration, userId from ResetPasswordTokens where token = ?"
			) else {
				throw Err.mysql
		}
		
		st.bindParam(token)
		
		guard st.execute() else {
			throw Err.mysql
		}
		
		let results = st.results()
		
		guard let row = results.next() else {
			throw Err.notFound
		}
		
		return (row[0] as! Int64, row[1] as! String)
	}
	
	func deleteResetPasswordToken(token: String) throws {
		let st = MySQLStmt(mysql)
		
		guard st.prepare(
			statement: "delete from ResetPasswordTokens where token = ?"
			) else {
				throw Err.mysql
		}
		
		st.bindParam(token)
		
		guard st.execute() else {
			throw Err.mysql
		}
	}
}
