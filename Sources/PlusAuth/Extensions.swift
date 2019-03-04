import Foundation

extension Dictionary {
	func toBytes() -> [UInt8] {
		do {
			let data = try JSONSerialization.data(withJSONObject: self, options: [])
			return [UInt8](data)
		} catch {
			return []
		}
	}
}

extension UUID {
	var bytes: [UInt8] {
		return Mirror(reflecting: uuid).children.map({$0.1 as! UInt8})
	}
	
	var data: Data {
		return Data(bytes: bytes)
	}
}

