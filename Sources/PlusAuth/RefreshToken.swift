import Foundation
import MySQLStORM
import StORM

public class RefreshToken: MySQLStORM {
  var value: String = ""
  var accountId: String = ""
  var expiration: Int = 0
  let plusAuth: PlusAuth
  
  public init(auth: PlusAuth) {
    plusAuth = auth
  }
  
  override open func table() -> String {
    return "\(plusAuth)RefreshToken"
  }
  
  public override func to(_ this: StORMRow) {
    value = this.data["value"] as? String ?? ""
    accountId = this.data["accountId"] as? String ?? ""
    expiration = this.data["expiration"] as? Int ?? 0
  }
  
  func rows() -> [RefreshToken] {
    var rows = [RefreshToken]()
    for i in 0..<self.results.rows.count {
      let row = RefreshToken(auth: plusAuth)
      row.to(self.results.rows[i])
      rows.append(row)
    }
    return rows
  }

}
