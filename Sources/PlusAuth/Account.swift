import Foundation
import MySQLStORM
import StORM

public class Account: MySQLStORM {
	public var id: String = ""
	public var username: String = ""
  public var hash: String = ""
  let plusAuth: PlusAuth
  
  init(auth: PlusAuth) {
    plusAuth = auth
  }
  
  public override func table() -> String {
    return "\(plusAuth.mySQLConfig.tablePrefix)Account"
  }
  
  public override func to(_ this: StORMRow) {
    id = this.data["id"] as? String ?? ""
    username = this.data["username"] as? String ?? ""
    hash = this.data["hash"] as? String ?? ""
  }
  
  func rows() -> [Account] {
    var rows = [Account]()
    for i in 0..<self.results.rows.count {
      let row = Account(auth: plusAuth)
      row.to(self.results.rows[i])
      rows.append(row)
    }
    return rows
  }
}
