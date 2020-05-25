// install jwt library
const jwt = require("jsonwebtoken")

function restrict() {
	return async (req, res, next) => {
		const authError = {
			message: "Invalid credentials",
		}

		try {
			// express-session will automatically get the session ID from the cookie
			// header, and check to make sure it's valid and the session for this user exists.
			// if (!req.session || !req.session.user) {
			// 	return res.status(401).json(authError)
			// }

			const token = req.headers.authorization

			if (!token) {
				return res.status(401).json(authError)
			}

			// check jwt signature received from client with our secret key
			jwt.verify(token, process.env.JWT_SECRET), (err, decodedPayload) => {
				// if the err is NOT empty then assume the user is NOT authenticated
				if (err) {
					return res.status(401).json(authError)
				}

				// otherwise we assume user IS validated
				// attach the decoded value to the request in case we need to access 
				// anything from that payload in a later middleware function or route 
				// handler we can call it from req.token
				req.token = decodedPayload
				// and then we move on
				next()
			}
		} catch(err) {
			next(err)
		}
	}
}

module.exports = restrict