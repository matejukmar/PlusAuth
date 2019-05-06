import Foundation

enum Err: Error {
	case mysql
	case request
	case notFound
	case unauthorized
	case expired
	case invalidPassword
	case unexpected
	case invalid
	case unverified
	case alreadyExists
}
