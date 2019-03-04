import Foundation
import PerfectMySQL

let mySQLDateFormat = "yyyy-MM-dd HH:mm:ss"

public struct MySQLConfig {
	public let host: String
	public let user: String
	public let password: String
	public let db: String
}

extension MySQL {
	static func new() throws -> MySQL {
		let mysql = MySQL()
		
		switch PlusAuth.shared.storageConfig {
		case .mysql(let config):
			let connection = mysql.connect(
				host: config.host,
				user: config.user,
				password: config.password
			)
			guard connection else {
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

extension Date {
	var mySQLStr: String {
		let df = DateFormatter()
		df.dateFormat = mySQLDateFormat
		return df.string(from: self)
	}
	
	init?(mySQLStr: String) {
		let df = DateFormatter()
		df.dateFormat = mySQLDateFormat
		if let date = df.date(from: mySQLStr) {
			self = date
		} else {
			return nil
		}
	}
}

class MySQLStorage: Storage {
	
	let mysql: MySQL
	init(mysql: MySQL) {
		self.mysql = mysql
	}
	
	func selectUserId(byEmail email: String) throws -> String {
		let st = MySQLStmt(mysql)
		guard st.prepare(statement: "select id from Users where email = ? and deleted = ?") else {
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
		return row[0] as! String
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
	
	func selectUserVerified(byEmail email: String) throws -> (id: String, verified: Bool) {
		let st = MySQLStmt(mysql)
		guard st.prepare(statement: "select id, verified from Users where email = ? and deleted = ?") else {
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
		return (row[0] as! String, (row[1] as! Int) > 0)
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
		return (row[1] as! Int) > 0
	}

	
	func insertUser(userId: String, email: String, hash: String) throws {
		let st = MySQLStmt(mysql)
		
		guard st.prepare(statement: "insert into Users (id, email, hash, verified, deleted) values (?, ?, ?, ?)") else {
			throw Err.mysql
		}
		st.bindParam(userId)
		st.bindParam(email)
		st.bindParam(hash)
		st.bindParam(0)
		st.bindParam(0)
		
		guard st.execute() else {
			print(mysql.errorMessage())
			throw Err.mysql
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

	
	func insertRefreshToken(userId: String, token: String, expiration: Int) throws {
		let st = MySQLStmt(mysql)
		guard st.prepare(statement: "insert into RefreshTokens (userId, token, expiration) values (?, ?, ?)") else {
			throw Err.mysql
		}
		st.bindParam(userId)
		st.bindParam(token)
		st.bindParam(expiration)
		
		guard st.execute() else {
			throw Err.mysql
		}
	}
	
	func selectRefreshToken(token: String) throws -> (expiration: Int, userId: String) {
		let st = MySQLStmt(mysql)
		
		guard st.prepare(
			statement: "select expiration, userId from RefreshTokens where token = ?"
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
		
		return (row[0] as! Int, row[1] as! String)
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
	
	
	func insertVerifyAccountToken(token: String, expiration: Int, userId: String) throws {
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
	
	func selectVerifyAccountToken(token: String) throws -> (expiration: Int, userId: String) {
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
		
		return (row[0] as! Int, row[1] as! String)
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
	
	func insertResetPasswordToken(token: String, expiration: Int, userId: String) throws {
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
	
	func selectResetPasswordToken(token: String) throws -> (expiration: Int, userId: String) {
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
		
		return (row[0] as! Int, row[1] as! String)
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
