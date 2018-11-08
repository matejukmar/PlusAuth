import Foundation
import MySQLStORM
import StORM

public class ResetPasswordToken: MySQLStORM {
  var value: String = ""
  var accountId: String = ""
  var expiration: Int = 0
  let plusAuth: PlusAuth
  
  public init(auth: PlusAuth) {
    plusAuth = auth
  }
  
  override open func table() -> String {
    return "\(plusAuth)ResetPasswordToken"
  }
  
  public override func to(_ this: StORMRow) {
    value = this.data["value"] as? String ?? ""
    accountId = this.data["accountId"] as? String ?? ""
    expiration = this.data["expiration"] as? Int ?? 0
  }
  
  func rows() -> [ResetPasswordToken] {
    var rows = [ResetPasswordToken]()
    for i in 0..<self.results.rows.count {
      let row = ResetPasswordToken(auth: plusAuth)
      row.to(self.results.rows[i])
      rows.append(row)
    }
    return rows
  }

}
