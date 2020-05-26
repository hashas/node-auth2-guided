const express = require("express")
const Users = require("./users-model")
const restrict = require("../middleware/restrict")

const router = express.Router()

// This endpoint is only available to logged-in users due to the `restrict` middleware
// Furthermore we want to restrict this endpoint to only "admin"
router.get("/", restrict("admin"), async (req, res, next) => {
	try {
		res.json(await Users.find())
	} catch(err) {
		next(err)
	}
})

module.exports = router 